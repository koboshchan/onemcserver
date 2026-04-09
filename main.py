import asyncio, json
from mc_packets import Encode, Decode

config = json.load(open("config.json", "r"))


async def handle_client(reader, writer):
    addr = writer.get_extra_info("peername")
    print(f"[*] Connection from {addr}")
    try:
        # 1. Receive Handshake
        raw_handshake = await reader.read(1024)
        handshake_data = Decode.handshake(raw_handshake)
        print(f"[C -> S] Handshake: {Decode.handshake(raw_handshake)}")
        if handshake_data["address"] not in config.keys():
            print(
                f"Received handshake for unknown domain {handshake_data['address']} from {addr}. Closing connection."
            )
            kick = Encode.disconnect(
                "Unknown domain. Please connect to a valid subdomain.",
                compression=False,
            )
            writer.write(kick)
            await writer.drain()
            raise ConnectionResetError("Unknown domain")
        if handshake_data["next_state"] == 1:
            print(f"received server list ping from {addr}.")
            try:
                reader_rem, writer_rem = await asyncio.open_connection(
                    config[handshake_data["address"]][0],
                    config[handshake_data["address"]][1],
                )
            except Exception as e:
                print(f"[!] Failed to connect to remote: {e}")
                writer.close()
                return

            writer_rem.write(raw_handshake)
            await writer_rem.drain()
            response1 = await reader_rem.read(8192)
            writer.write(response1)
            await writer.drain()
            print(f"[S -> C] Server List Ping response sent to {addr}.")
            writer_rem.close()
            await writer_rem.wait_closed()
            return
        else:
            print(f"received login handshake from {addr}.")
            # 2. Receive Login Start
            raw_login = await reader.read(4096)
            if not raw_login:
                raise ConnectionResetError(
                    "Client closed connection before Login Start"
                )
            print(f"[C -> S] Login Start: {Decode.login_start(raw_login)}")

            # 3. SEND SET COMPRESSION
            # The Set Compression packet (ID 0x03) needs to be framed correctly.
            # [Packet Length] [ID 0x03] [Threshold (VarInt)]
            compression_payload = Encode.encode_varint(0x03) + Encode.encode_varint(256)
            writer.write(
                Encode.encode_varint(len(compression_payload)) + compression_payload
            )
            await writer.drain()
            print("[S -> C] Set Compression sent.")

            # 4. SEND LOGIN SUCCESS
            # CRITICAL: This MUST be True because Set Compression is now active
            writer.write(Encode.login_success(compression=True))
            await writer.drain()
            print("[S -> C] Login Success (Compressed Format) sent.")

            # 5. WAIT FOR LOGIN ACKNOWLEDGED
            raw_ack = await reader.read(4096)
            print(f"[C -> S] Login Acknowledged: {Decode.login_acknowledged(raw_ack)}")

            # 6. WAIT FOR CLIENT CONFIG PACKETS
            raw_config = await reader.read(4096)
            print(f"[C -> S] Client Config: {Decode.client_config(raw_config)}")

            # 7. SEND SERVER CONFIG PACKETS
            writer.write(Encode.brand("onemcserver", compression=True))
            # Known Packs packet (0x0E) - Required by 1.21.10+
            writer.write(Encode.select_known_packs(version="1.21.10", compression=True))
            await writer.drain()

            # 8. FINAL KICK: Transfer
            writer.write(
                Encode.transfer(
                    config[handshake_data["address"]][0],
                    config[handshake_data["address"]][1],
                )
            )
            await writer.drain()

            print(
                f"[S -> C] Transferred to{config[handshake_data['address']][0]}:{config[handshake_data['address']][1]} sent to {addr}"
            )

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
