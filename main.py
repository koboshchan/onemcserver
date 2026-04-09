import asyncio
import struct
import json


def encode_varint(val):
    total = b""
    while True:
        byte = val & 0x7F
        val >>= 7
        if val:
            total += struct.pack("B", byte | 0x80)
        else:
            total += struct.pack("B", byte)
            return total


def create_transfer_packet(host="server.kobosh.com", port=25565, compression=True):
    """
    Creates a Transfer packet (ID 0x0b) for the Configuration state.
    """
    packet_id = 0x0B

    # Field 1: Host (String 32767)
    host_bytes = host.encode("utf-8")
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


async def handle_client(reader, writer):
    addr = writer.get_extra_info("peername")
    print(f"[*] Connection from {addr}")
    try:
        # 1. Receive Handshake (C -> S 17 bytes)
        await reader.read(1024)
        # 2. Receive Login Start (C -> S 25 bytes)
        await reader.read(1024)

        # 3. SEND SET COMPRESSION (S -> C 4 bytes: 03 03 80 02)
        # ID 0x03, Threshold 256 (80 02)
        writer.write(bytes.fromhex("03 03 80 02"))
        await writer.drain()
        print("[S -> C] Set Compression sent.")

        # 4. SEND LOGIN SUCCESS (S -> C)
        uuid_hex = "ba096d9aed4a3689b7502eed340ad2cd"
        username = "kobosh"
        login_success_body = (
            bytes.fromhex(uuid_hex)
            + encode_varint(len(username))
            + username.encode()
            + b"\x00"
        )
        writer.write(create_raw_packet(0x02, login_success_body, compression=True))
        await writer.drain()
        print("[S -> C] Login Success sent.")

        # 5. WAIT FOR LOGIN ACKNOWLEDGED (C -> S 3 bytes: 02 00 03)
        await reader.read(1024)
        print("[C -> S] Login Acknowledged received. State: CONFIG.")

        # 6. WAIT FOR CLIENT CONFIG PACKETS (Brand, Info, etc.)
        await reader.read(1024)

        # 7. SEND SERVER CONFIG PACKETS (Brand: Purpur, Version, etc.)
        # Brand 'Purpur'
        brand = encode_varint(len("Purpur")) + "Purpur".encode()
        writer.write(create_raw_packet(0x01, brand, compression=True))

        # Version '1.21.10'
        version_body = (
            b"\x01"
            + encode_varint(len("minecraft"))
            + b"minecraft"
            + encode_varint(len("core"))
            + b"core"
            + encode_varint(len("1.21.10"))
            + b"1.21.10"
        )
        writer.write(create_raw_packet(0x0E, version_body, compression=True))
        await writer.drain()

        # 8. FINAL KICK: "success"
        packet = create_transfer_packet("donutsmp.net", 25565, compression=True)
        writer.write(packet)
        await writer.drain()

        print(f"[S -> C] Transferred to {addr}")

    except Exception as e:
        print(f"Error handling {addr}: {e}")
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    HOST = "0.0.0.0"
    PORT = 25565
    server = await asyncio.start_server(handle_client, HOST, PORT)
    print(f"Listening on {PORT}...")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
