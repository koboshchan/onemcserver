import asyncio
from mc_packets import Encode, Decode


async def handle_client(reader, writer):
    addr = writer.get_extra_info("peername")
    print(f"[*] Connection from {addr}")
    try:
        # 1. Receive Handshake
        raw_handshake = await reader.read(1024)
        print(f"[C -> S] Handshake: {Decode.handshake(raw_handshake)}")

        # 2. Receive Login Start
        raw_login = await reader.read(1024)
        print(f"[C -> S] Login Start: {Decode.login_start(raw_login)}")

        # 3. SEND SET COMPRESSION
        writer.write(Encode.set_compression(256, compression=False))
        await writer.drain()
        print("[S -> C] Set Compression sent.")

        # 4. SEND LOGIN SUCCESS
        writer.write(Encode.login_success())
        await writer.drain()
        print("[S -> C] Login Success sent.")

        # 5. WAIT FOR LOGIN ACKNOWLEDGED
        raw_ack = await reader.read(1024)
        print(f"[C -> S] Login Acknowledged: {Decode.login_acknowledged(raw_ack)}")

        # 6. WAIT FOR CLIENT CONFIG PACKETS
        raw_config = await reader.read(1024)
        print(f"[C -> S] Client Config: {Decode.client_config(raw_config)}")

        # 7. SEND SERVER CONFIG PACKETS
        writer.write(Encode.brand("Onemcserver"))
        writer.write(Encode.version())
        await writer.drain()

        # 8. FINAL KICK: Transfer
        writer.write(Encode.transfer("donutsmp.net", 25565))
        await writer.drain()

        print(f"[S -> C] Transferred to {addr}")

    except Exception as e:
        if not isinstance(e, ConnectionResetError) and not isinstance(
            e, BrokenPipeError
        ):
            print(f"Error handling {addr}: {e}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass


async def main():
    HOST = "0.0.0.0"
    PORT = 25565
    server = await asyncio.start_server(handle_client, HOST, PORT)
    print(f"Listening on {PORT}...")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
