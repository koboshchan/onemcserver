import struct

def encode_varint(val):
    """Encodes an integer into Minecraft VarInt bytes."""
    total = b""
    while True:
        byte = val & 0x7F
        val >>= 7
        if val:
            total += struct.pack("B", byte | 0x80)
        else:
            total += struct.pack("B", byte)
            return total

def read_varint(sock):
    """Reads a Minecraft VarInt from a socket."""
    val = 0
    for i in range(5):
        b = sock.recv(1)
        if not b: return None
        byte = b[0]
        val |= (byte & 0x7F) << (7 * i)
        if not (byte & 0x80):
            break
    return val

def encode_string(string):
    """Encodes a string as a VarInt length followed by UTF-8 bytes."""
    data = string.encode("utf-8")
    return encode_varint(len(data)) + data

def read_string(sock):
    """Reads a VarInt length followed by UTF-8 bytes from a socket."""
    length = read_varint(sock)
    if length is None: return None
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk: return None
        data += chunk
    return data.decode("utf-8")

def create_packet(packet_id, data):
    """Wraps packet ID and data with a VarInt length header."""
    packet_id_encoded = encode_varint(packet_id)
    payload = packet_id_encoded + data
    return encode_varint(len(payload)) + payload

def read_packet(sock):
    """Reads a full packet and returns (packet_id, data)."""
    length = read_varint(sock)
    if length is None: return None, None
    packet_data = b""
    while len(packet_data) < length:
        chunk = sock.recv(length - len(packet_data))
        if not chunk: return None, None
        packet_data += chunk
    
    # Decode the Packet ID VarInt from the start of the payload
    val = 0
    id_len = 0
    for i in range(5):
        byte = packet_data[i]
        val |= (byte & 0x7F) << (7 * i)
        id_len += 1
        if not (byte & 0x80):
            break
    return val, packet_data[id_len:]