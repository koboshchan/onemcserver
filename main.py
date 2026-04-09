import asyncio, json
from mc_packets import Encode, Decode, get_version_handler

try:
    config = json.load(open("config.json", "r"))
except FileNotFoundError:
    print("[!] ERROR: config.json not found. Did you mount the volume?")
    exit(1)


async def read_varint_from_stream(reader, max_bytes=5):
    value = 0
    for i in range(max_bytes):
        byte = (await reader.readexactly(1))[0]
        value |= (byte & 0x7F) << (7 * i)
        if not (byte & 0x80):
            return value
    raise ValueError("VarInt too long")


async def read_packet(reader):
    packet_length = await read_varint_from_stream(reader)
    payload = await reader.readexactly(packet_length)
    return Encode.encode_varint(packet_length) + payload


async def handle_client(reader, writer):
    addr = writer.get_extra_info("peername")
    print(f"[*] Connection from {addr}")
    try:
        # 1. Receive Handshake
        raw_handshake = await read_packet(reader)
        if not raw_handshake:
            raise ConnectionResetError(
                "Client closed connection before sending handshake"
            )
        handshake_data = Decode.handshake(raw_handshake)
        packet_handler = get_version_handler(handshake_data["protocol_version"])
        print(f"[C -> S] Handshake: {Decode.handshake(raw_handshake)}")
        if handshake_data["address"] not in config.keys():
            if handshake_data["next_state"] == 1:
                print(
                    f"Received ping for unknown domain {handshake_data['address']} from {addr}. Sending fake response."
                )
                try:
                    # Read the Status Request packet (ID 0x00)
                    await read_packet(reader)
                    # Construct and send Status Response
                    json_response = {
                        "version": {"name": "onemcserver", "protocol": 0},
                        "players": {"max": 0, "online": 0},
                        "description": {"text": "Unknown Domain"},
                    }
                    response_packet = Encode.status_response(
                        json_response, compression=False
                    )
                    writer.write(response_packet)
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return
                except Exception as e:
                    print(f"[!] Ping error for unknown domain: {e}")
                    writer.close()
                    return
            print(
                f"Received handshake for unknown domain {handshake_data['address']} from {addr}. Closing connection."
            )
            kick = packet_handler.disconnect(
                "Unknown domain. Please connect to a valid subdomain.",
                compression=False,
            )
            writer.write(kick)
            await writer.drain()
            raise ConnectionResetError("Unknown domain")
        if handshake_data["next_state"] == 1:
            print(f"received server list ping from {addr}.")
            try:
                reader_rem, writer_rem = await asyncio.wait_for(
                    asyncio.open_connection(
                        config[handshake_data["address"]][0],
                        config[handshake_data["address"]][1],
                    ),
                    timeout=2.0,
                )
                writer_rem.write(raw_handshake)
                await writer_rem.drain()

                response1 = await asyncio.wait_for(reader_rem.read(8192), timeout=2.0)

                writer.write(response1)
                await writer.drain()
                print(f"[S -> C] Server List Ping response sent to {addr}.")
                writer_rem.close()
                await writer_rem.wait_closed()
            except (asyncio.TimeoutError, Exception) as e:
                print(f"[!] Ping failed for {handshake_data['address']}: {e}")
                # Send "Server Offline" status response
                json_response = {
                    "version": {"name": "Offline", "protocol": 0},
                    "players": {"max": 0, "online": 0},
                    "description": {"text": "§cServer is offline"},
                }
                response_packet = Encode.status_response(
                    json_response, compression=False
                )
                writer.write(response_packet)
                await writer.drain()

            writer.close()
            await writer.wait_closed()
            return
        else:
            print(f"received login handshake from {addr}.")
            # 2. Receive Login Start
            raw_login = await read_packet(reader)
            if not raw_login:
                raise ConnectionResetError(
                    "Client closed connection before Login Start"
                )
            print(f"[C -> S] Login Start: {Decode.login_start(raw_login)}")

            # 3. SEND SET COMPRESSION
            writer.write(
                packet_handler.set_compression(threshold=256, compression=False)
            )
            await writer.drain()
            print("[S -> C] Set Compression sent.")

            # 4. SEND LOGIN SUCCESS
            # CRITICAL: This MUST be True because Set Compression is now active
            writer.write(packet_handler.login_success(compression=True))
            await writer.drain()
            print("[S -> C] Login Success (Compressed Format) sent.")

            # 5. WAIT FOR LOGIN ACKNOWLEDGED
            raw_ack = await read_packet(reader)
            print(f"[C -> S] Login Acknowledged: {Decode.login_acknowledged(raw_ack)}")

            # 6. WAIT FOR CLIENT CONFIG PACKETS
            raw_config = await read_packet(reader)
            print(f"[C -> S] Client Config: {Decode.client_config(raw_config)}")

            # 7. SEND SERVER CONFIG PACKETS
            writer.write(packet_handler.brand("onemcserver", compression=True))
            # Known Packs packet (0x0E) - Required by 1.21.10+
            writer.write(
                packet_handler.select_known_packs(version="1.21.10", compression=True)
            )
            await writer.drain()

            # 8. FINAL KICK: Transfer
            writer.write(
                packet_handler.transfer(
                    config[handshake_data["address"]][0],
                    config[handshake_data["address"]][1],
                )
            )
            await writer.drain()

            print(
                f"[S -> C] Transferred to{config[handshake_data['address']][0]}:{config[handshake_data['address']][1]} sent to {addr}"
            )

    except Exception as e:
        if isinstance(
            e, (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError)
        ):
            pass  # Expected disconnections, don't log
        elif isinstance(e, ValueError):
            print(f"[!] Malformed packet from {addr}: {e}")
        else:
            print(f"[!] Error handling {addr}: {e}")
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
