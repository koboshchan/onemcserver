import asyncio, json, requests, hashlib, uuid, zlib, struct
from mc_packets import Encode, Decode
from mc_crypto import minecraft_sha1, MinecraftCipher, EncryptionContext
from mc_protocol import get_packet_id

try:
    config_list = json.load(open("config.json", "r"))
    config = {item["host"].lower(): item for item in config_list}
    print(f"[*] Loaded config for hosts: {', '.join(config.keys())}")
except FileNotFoundError:
    print("[!] ERROR: config.json not found.")
    exit(1)


class MinecraftStream:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.cipher = None
        self.compression_threshold = -1
        self.protocol_version = 767

    def enable_encryption(self, shared_secret):
        self.cipher = MinecraftCipher(shared_secret)

    async def _read(self, n):
        data = await self.reader.readexactly(n)
        if self.cipher:
            data = self.cipher.decrypt(data)
        return data

    async def read_varint(self):
        value = 0
        for i in range(5):
            byte_data = await self._read(1)
            b = byte_data[0]
            value |= (b & 0x7F) << (7 * i)
            if not (b & 0x80):
                return value
        raise ValueError("VarInt too long")

    async def read_packet(self):
        length = await self.read_varint()
        data = await self._read(length)
        if self.compression_threshold >= 0:
            data_len, offset = Decode._read_varint(data, 0)
            if data_len > 0:
                data = zlib.decompress(data[offset:])
            else:
                data = data[offset:]
        return data

    def write_packet(self, packet_name, state, data, force_uncompressed=False):
        packet_id = get_packet_id(self.protocol_version, state, "toClient", packet_name)
        if packet_id is None:
            print(f"[!] ID not found for {packet_name}")
            return
        payload = Encode.encode_varint(packet_id) + data
        if self.compression_threshold >= 0 and not force_uncompressed:
            if len(payload) >= self.compression_threshold:
                compressed = zlib.compress(payload)
                data_framed = Encode.encode_varint(len(payload)) + compressed
            else:
                data_framed = Encode.encode_varint(0) + payload
        else:
            data_framed = payload
        full_packet = Encode.encode_varint(len(data_framed)) + data_framed
        if self.cipher:
            full_packet = self.cipher.encrypt(full_packet)
        self.writer.write(full_packet)

    async def drain(self):
        await self.writer.drain()

    def close(self):
        self.writer.close()


async def get_premium_profile(username):
    url = f"https://api.mojang.com/users/profiles/minecraft/{username}"
    try:
        res = requests.get(url, timeout=3)
        if res.status_code == 200:
            return res.json()
    except:
        pass
    return None


async def verify_has_joined(username, server_hash):
    url = f"https://sessionserver.mojang.com/session/minecraft/hasJoined?username={username}&serverId={server_hash}"
    try:
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            return res.json()
    except:
        pass
    return None


async def handle_client(reader, writer):
    stream = MinecraftStream(reader, writer)
    addr = writer.get_extra_info("peername")
    print(f"[*] Connection from {addr}")

    try:
        # 1. Handshake
        raw_handshake = await stream.read_packet()
        handshake = Decode.handshake(raw_handshake)
        stream.protocol_version = handshake["protocol_version"]
        host = handshake["address"].split("\0")[0].lower()

        entry = config.get(host)
        if not entry:
            if handshake["next_state"] == 1:
                await stream.read_packet()
                stream.writer.write(
                    Encode.status_response(
                        {
                            "version": {"name": "onemcserver", "protocol": 0},
                            "players": {"max": 0, "online": 0},
                            "description": {"text": "Unknown Domain"},
                        }
                    )
                )
                await stream.drain()
            else:
                stream.write_packet(
                    "disconnect", "login", Encode.disconnect(f"Unknown domain: {host}")
                )
                await stream.drain()
            stream.close()
            return

        target_host, target_port = entry["transfer_to"]
        allow_cracked = entry.get("cracked_players", False)

        if handshake["next_state"] == 1:
            print(f"[*] Status ping for {host} (Proto: {stream.protocol_version})")
            try:
                r_rem, w_rem = await asyncio.wait_for(
                    asyncio.open_connection(target_host, target_port), timeout=2.0
                )
                hs_payload = (
                    Encode.encode_varint(0x00)
                    + Encode.encode_varint(handshake["protocol_version"])
                    + Encode.encode_string(handshake["address"])
                    + struct.pack(">H", handshake["port"])
                    + Encode.encode_varint(1)
                )
                w_rem.write(Encode.encode_varint(len(hs_payload)) + hs_payload)

                async def pipe(r, w):
                    try:
                        while True:
                            d = await r.read(8192)
                            if not d:
                                break
                            w.write(d)
                            await w.drain()
                    except:
                        pass
                    finally:
                        w.close()

                asyncio.create_task(pipe(reader, w_rem))
                await pipe(r_rem, writer)
            except:
                stream.writer.write(
                    Encode.status_response(
                        {
                            "version": {"name": "offline", "protocol": 0},
                            "players": {"max": 0, "online": 0},
                            "description": {"text": "§cServer Offline"},
                        }
                    )
                )
                await stream.drain()
                stream.close()
            return

        # 2. Login Start
        raw_login_start = await stream.read_packet()
        login_start = Decode.login_start(raw_login_start)
        username = login_start["username"]

        premium_profile = await get_premium_profile(username)
        user_uuid = None
        properties = []

        if premium_profile:
            print(f"[*] {username} might be PREMIUM. Sending Encryption Request.")
            ctx = EncryptionContext()
            stream.write_packet(
                "encryption_begin",
                "login",
                Encode.encryption_request(ctx.public_key_der, ctx.verify_token),
            )
            await stream.drain()

            raw_encryption_res = await stream.read_packet()
            enc_res = Decode.encryption_response(raw_encryption_res)
            shared_secret = ctx.decrypt_shared_secret(enc_res["shared_secret"])
            verify_token = ctx.decrypt_verify_token(enc_res["verify_token"])

            if verify_token == ctx.verify_token:
                stream.enable_encryption(shared_secret)
                server_hash = minecraft_sha1(b"", shared_secret, ctx.public_key_der)
                verified_profile = await verify_has_joined(username, server_hash)
                if verified_profile:
                    print(f"[+] {username} is ONLINE (Premium)")
                    user_uuid = str(uuid.UUID(verified_profile["id"]))
                    properties = verified_profile.get("properties", [])
                else:
                    print(
                        f"[!] {username} failed verification. Kicking (Premium name theft)."
                    )
                    stream.write_packet(
                        "disconnect",
                        "login",
                        Encode.disconnect(
                            "That name is registered to a premium account. Please log in with your official account."
                        ),
                    )
                    await stream.drain()
                    stream.close()
                    return
            else:
                stream.write_packet(
                    "disconnect", "login", Encode.disconnect("Invalid verify token")
                )
                await stream.drain()
                stream.close()
                return
        else:
            if not allow_cracked:
                print(
                    f"[!] {username} is cracked and cracked players are disabled for {host}. Kicking."
                )
                stream.write_packet(
                    "disconnect",
                    "login",
                    Encode.disconnect("This server is in Online Mode."),
                )
                await stream.drain()
                stream.close()
                return
            print(f"[-] {username} is CRACKED (Offline - non-premium name)")
            user_uuid = str(uuid.uuid3(uuid.NAMESPACE_DNS, f"OfflinePlayer:{username}"))

        stream.write_packet(
            "compress", "login", Encode.set_compression(256), force_uncompressed=True
        )
        await stream.drain()
        stream.compression_threshold = 256

        stream.write_packet(
            "success", "login", Encode.login_success(user_uuid, username, properties)
        )
        await stream.drain()

        await stream.read_packet()  # Login Acknowledged

        stream.write_packet(
            "custom_payload", "configuration", Encode.brand("onemcserver")
        )
        stream.write_packet(
            "select_known_packs", "configuration", Encode.select_known_packs("1.21.1")
        )

        print(f"[*] Transferring {username} to {target_host}:{target_port}")
        stream.write_packet(
            "transfer", "configuration", Encode.transfer(target_host, target_port)
        )
        await stream.drain()

    except Exception as e:
        if not isinstance(e, (asyncio.IncompleteReadError, ConnectionResetError)):
            import traceback

            traceback.print_exc()
    finally:
        stream.close()


async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", 25565)
    print("Listening on 25565 (Hybrid Multi-Version Proxy)...")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
