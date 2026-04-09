import socket
import struct
import json

def encode_varint(val):
    total = b''
    while True:
        byte = val & 0x7F
        val >>= 7
        if val:
            total += struct.pack('B', byte | 0x80)
        else:
            total += struct.pack('B', byte)
            return total
def create_transfer_packet(host="server.kobosh.com", port=25565, compression=True):
    """
    Creates a Transfer packet (ID 0x0b) for the Configuration state.
    """
    packet_id = 0x0b
    
    # Field 1: Host (String 32767)
    host_bytes = host.encode('utf-8')
    host_field = encode_varint(len(host_bytes)) + host_bytes
    
    # Field 2: Port (VarInt)
    port_field = encode_varint(port)
    
    # Combine fields
    data = host_field + port_field
    body = encode_varint(packet_id) + data
    
    # Wrap in compression header (VarInt 0 for uncompressed)
    if compression:
        body = encode_varint(0) + body
        
    # Final packet: [Total Length] [Body]
    return encode_varint(len(body)) + body
def create_kick_packet(message, state="login", compression=False):
    """
    Creates a disconnect packet for Minecraft 1.21.10.
    
    :param message: The text to display to the user.
    :param state: 'login' or 'config' (determines ID and format).
    :param compression: Boolean, whether a compression threshold was set.
    """
    if state.lower() == "login":
        # ID 0x00, Format: JSON String
        packet_id = 0x00
        json_message = json.dumps({"text": message})
        data = encode_varint(len(json_message)) + json_message.encode('utf-8')
    else:
        # ID 0x02, Format: Binary NBT (required for 1.20.5+)
        packet_id = 0x02
        # Minimal NBT Compound for {text: "message"}
        # 0a: Compound, 08: String Tag, 0004: "text", len: message_len, data: message, 00: End
        message_bytes = message.encode('utf-8')
        data = (b'\x0a\x08\x00\x04text' + 
                struct.pack('>H', len(message_bytes)) + 
                message_bytes + b'\x00')

    # Construct payload
    payload = encode_varint(packet_id) + data
    
    # Handle packet framing
    if compression:
        # [Packet Len] [Data Len (0 for uncompressed)] [ID] [Data]
        final_payload = encode_varint(0) + payload
    else:
        # [Packet Len] [ID] [Data]
        final_payload = payload
        
    return encode_varint(len(final_payload)) + final_payload

def create_raw_packet(packet_id, data, compression=False):
    """
    Wraps packet ID and data. 
    If compression is enabled, it adds the 'Data Length' VarInt (0 for uncompressed).
    """
    payload = encode_varint(packet_id) + data
    if compression:
        # After Set Compression, packet format is: [Packet Length] [Data Length] [Data]
        # For uncompressed packets, Data Length is 0.
        payload = encode_varint(0) + payload
    
    return encode_varint(len(payload)) + payload

def main():
    HOST = '0.0.0.0'
    PORT = 25565
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"Listening on {PORT}...")

    while True:
        conn, addr = server.accept()
        print(f"[*] Connection from {addr}")
        try:
            # 1. Receive Handshake (C -> S 17 bytes)
            conn.recv(1024) 
            # 2. Receive Login Start (C -> S 25 bytes)
            conn.recv(1024)

            # 3. SEND SET COMPRESSION (S -> C 4 bytes: 03 03 80 02)
            # ID 0x03, Threshold 256 (80 02)
            conn.sendall(bytes.fromhex("03 03 80 02"))
            print("[S -> C] Set Compression sent.")

            # 4. SEND LOGIN SUCCESS (S -> C)
            # We use compression=True from here on.
            # Payload: UUID + Username + Property Count (0) + Strict Error (False)
            uuid_hex = "ba096d9aed4a3689b7502eed340ad2cd"
            username = "kobosh"
            login_success_body = bytes.fromhex(uuid_hex) + encode_varint(len(username)) + username.encode() + b'\x00'
            conn.sendall(create_raw_packet(0x02, login_success_body, compression=True))
            print("[S -> C] Login Success sent.")

            # 5. WAIT FOR LOGIN ACKNOWLEDGED (C -> S 3 bytes: 02 00 03)
            conn.recv(1024)
            print("[C -> S] Login Acknowledged received. State: CONFIG.")

            # 6. WAIT FOR CLIENT CONFIG PACKETS (Brand, Info, etc.)
            # We drain the buffer as the client sends its settings
            conn.recv(1024)

            # 7. SEND SERVER CONFIG PACKETS (Brand: Purpur, Version, etc.)
            # Brand 'Purpur'
            brand = encode_varint(len("Purpur")) + "Purpur".encode()
            conn.sendall(create_raw_packet(0x01, brand, compression=True))
            
            # Version '1.21.10'
            version_body = b'\x01' + encode_varint(len("minecraft")) + b"minecraft" + \
                           encode_varint(len("core")) + b"core" + \
                           encode_varint(len("1.21.10")) + b"1.21.10"
            conn.sendall(create_raw_packet(0x0e, version_body, compression=True))

            # 8. FINAL KICK: "success" (ID 0x00 in Config/Play state is Disconnect)
            # State must be 'config' and compression must be True
            packet = create_transfer_packet("donutsmp.net", 25565, compression=True)
            conn.sendall(packet)
            
            print("[S -> C] Transferred")
            
        except Exception as e:
            print(f"Error: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    main()