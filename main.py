import asyncio, json, requests, hashlib, uuid, zlib, struct, os, time, base64
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from mc_packets import Encode, Decode
from mc_crypto import minecraft_sha1, MinecraftCipher, EncryptionContext
from mc_protocol import get_packet_id, load_login_packet, resolve_login_packet_version
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding as CryptoEncoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

# MongoDB Setup
mongo_client = AsyncIOMotorClient("mongodb://mongo:27017")
db = mongo_client.onemcserver
cache_col = db.user_cache


async def init_db():
    # Create TTL index that expires documents 1 hour (3600 seconds) after the 'created' time
    await cache_col.create_index("created", expireAfterSeconds=3600)
    print("[*] MongoDB Cache Initialized")


config_data = {}
try:
    config_data = json.load(open("config.json", "r"))
    # Support both old format (array) and new format (object with servers key)
    if isinstance(config_data, list):
        config_list = config_data
        config = {item["host"].lower(): item for item in config_list}
        global_config = {}
    else:
        config_list = config_data.get("servers", [])
        config = {item["host"].lower(): item for item in config_list}
        global_config = {k: v for k, v in config_data.items() if k != "servers"}
    print(f"[*] Loaded config for hosts: {', '.join(config.keys())}")
except FileNotFoundError:
    print("[!] ERROR: config.json not found.")
    exit(1)


# --- Ed25519 Key Management ---
_signing_private_key: Ed25519PrivateKey = None
_signing_public_key_hex: str = ""


def _decode_key(value: str) -> bytes:
    """Accept either hex or base64-encoded key bytes."""
    try:
        return bytes.fromhex(value)
    except ValueError:
        import binascii
        try:
            return base64.b64decode(value)
        except (binascii.Error, ValueError):
            raise ValueError(f"Key is neither valid hex nor base64: {value!r}")


def _load_or_generate_keys():
    global _signing_private_key, _signing_public_key_hex, config_data
    priv_raw = global_config.get("private_key", "").strip()
    pub_raw = global_config.get("public_key", "").strip()

    if not priv_raw or not pub_raw:
        _signing_private_key = Ed25519PrivateKey.generate()
        priv_bytes = _signing_private_key.private_bytes(
            CryptoEncoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        pub_bytes = _signing_private_key.public_key().public_bytes(
            CryptoEncoding.Raw, PublicFormat.Raw
        )
        priv_hex = priv_bytes.hex()
        pub_hex = pub_bytes.hex()
        config_data["private_key"] = priv_hex
        config_data["public_key"] = pub_hex
        global_config["private_key"] = priv_hex
        global_config["public_key"] = pub_hex
        with open("config.json", "w") as f:
            json.dump(config_data, f, indent=4)
        print("[*] Generated new Ed25519 key pair and saved to config.json")
    else:
        priv_bytes = _decode_key(priv_raw)
        pub_bytes = _decode_key(pub_raw)
        _signing_private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        priv_hex = priv_bytes.hex()
        pub_hex = pub_bytes.hex()
        # Migrate to hex if keys were stored in another format
        if priv_raw != priv_hex or pub_raw != pub_hex:
            config_data["private_key"] = priv_hex
            config_data["public_key"] = pub_hex
            global_config["private_key"] = priv_hex
            global_config["public_key"] = pub_hex
            with open("config.json", "w") as f:
                json.dump(config_data, f, indent=4)
            print("[*] Migrated keys to hex format in config.json")

    _signing_public_key_hex = pub_hex

def build_auth_cookie(username, user_uuid_str, is_cracked):
    """Build cookie value: minified JSON bytes + hex-encoded Ed25519 signature (128 ASCII chars)."""
    payload = json.dumps(
        {
            "username": username,
            "uuid": user_uuid_str,
            "cracked": is_cracked,
            "time": int(time.time()),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    signature = _signing_private_key.sign(payload)
    return payload + signature.hex().encode("ascii")


def get_translation(key, *args):
    """Get a translation string with optional formatting arguments."""
    translations = global_config.get("translations", {})
    text = translations.get(key, key)
    # Support %s formatting if args provided
    if args:
        return text % args if "%s" in text else text
    return text


def parse_client_core_version_from_known_packs(packet):
    """Parse client known-packs response and extract minecraft:core version hint."""
    try:
        _, offset = Decode._read_varint(packet, 0)
        count, offset = Decode._read_varint(packet, offset)
        for _ in range(count):
            namespace, offset = Decode._read_string(packet, offset)
            pack_id, offset = Decode._read_string(packet, offset)
            version, offset = Decode._read_string(packet, offset)
            if namespace == "minecraft" and pack_id == "core":
                return version
    except Exception:
        return None
    return None


def _collect_tag_refs(value, refs):
    if isinstance(value, str):
        if value.startswith("#"):
            refs.add(value[1:])
        return
    if isinstance(value, dict):
        for v in value.values():
            _collect_tag_refs(v, refs)
        return
    if isinstance(value, list):
        for v in value:
            _collect_tag_refs(v, refs)


def build_configuration_tags_packet(codec):
    """Build configuration tags from tag references present in registry entries."""
    registries = []
    for reg_id, reg_data in codec.items():
        entries = reg_data.get("entries", [])
        if not entries:
            continue

        refs = set()
        for entry in entries:
            _collect_tag_refs(entry.get("value"), refs)

        if not refs:
            continue

        # Use all entry indices as a permissive fallback membership set.
        # This avoids unbound tags causing client-side registry load failures.
        indices = list(range(len(entries)))
        registries.append((reg_id, sorted(refs), indices))

    body = Encode.encode_varint(len(registries))
    for reg_id, tags, indices in registries:
        body += Encode.encode_string(reg_id)
        body += Encode.encode_varint(len(tags))
        for tag_name in tags:
            body += Encode.encode_string(tag_name)
            body += Encode.encode_varint(len(indices))
            for idx in indices:
                body += Encode.encode_varint(idx)
    return body


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
    # Check MongoDB cache first
    cached = await cache_col.find_one({"name": username})
    if cached:
        if cached.get("microsoft"):
            return {"id": cached["uuid"], "name": cached["name"]}
        return None

    url = f"https://api.mojang.com/users/profiles/minecraft/{username}"
    try:
        res = requests.get(url, timeout=3)
        if res.status_code == 200:
            profile = res.json()
            await cache_col.update_one(
                {"name": username},
                {
                    "$set": {
                        "microsoft": True,
                        "uuid": profile["id"],
                        "created": datetime.now(timezone.utc),
                    }
                },
                upsert=True,
            )
            return profile
        elif res.status_code == 204:  # No content = cracked
            await cache_col.update_one(
                {"name": username},
                {
                    "$set": {
                        "microsoft": False,
                        "uuid": None,
                        "created": datetime.now(timezone.utc),
                    }
                },
                upsert=True,
            )
            return None
    except Exception as e:
        print(f"[!] Error checking Mojang API: {e}")
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
                motd_text = get_translation("domain.unknown.motd")
                stream.writer.write(
                    Encode.status_response(
                        {
                            "version": {"name": "onemcserver", "protocol": 0},
                            "players": {"max": 0, "online": 0},
                            "description": {"text": motd_text},
                        }
                    )
                )
                await stream.drain()
            else:
                disconnect_text = get_translation("domain.unknown.disconnect", host)
                stream.write_packet(
                    "disconnect", "login", Encode.disconnect(disconnect_text)
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
                motd_text = get_translation("server.offline.motd")
                stream.writer.write(
                    Encode.status_response(
                        {
                            "version": {"name": "offline", "protocol": 0},
                            "players": {"max": 0, "online": 0},
                            "description": {"text": "§c" + motd_text},
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
        is_premium = False

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
                    is_premium = True
                else:
                    print(f"[!] {username} failed verification. Kicking.")
                    disconnect_text = get_translation("authentication.failed.disconnect")
                    stream.write_packet(
                        "disconnect",
                        "login",
                        Encode.disconnect(disconnect_text),
                    )
                    await stream.drain()
                    stream.close()
                    return
            else:
                token_text = get_translation("token.invalid.disconnect")
                stream.write_packet(
                    "disconnect", "login", Encode.disconnect(token_text)
                )
                await stream.drain()
                stream.close()
                return
        else:
            if not allow_cracked:
                print(
                    f"[!] {username} is cracked and cracked players are disabled for {host}. Kicking."
                )
                online_mode_text = get_translation("online.mode.disconnect")
                stream.write_packet(
                    "disconnect",
                    "login",
                    Encode.disconnect(online_mode_text),
                )
                await stream.drain()
                stream.close()
                return
            print(f"[-] {username} is CRACKED")
            user_uuid = str(uuid.uuid3(uuid.NAMESPACE_DNS, f"OfflinePlayer:{username}"))

        stream.write_packet(
            "compress", "login", Encode.set_compression(256), force_uncompressed=True
        )
        await stream.drain()
        stream.compression_threshold = 256

        stream.write_packet(
            "success", "login", Encode.login_success(user_uuid, username, properties, stream.protocol_version)
        )
        await stream.drain()
        print(f"[*] Sent Login Success to {username}")

        try:
            await asyncio.wait_for(
                stream.read_packet(), timeout=5.0
            )  # Login Acknowledged
            print(f"[*] Received Login Acknowledged from {username}")
        except asyncio.TimeoutError:
            print(f"[!] Timeout waiting for Login Acknowledged from {username}")
            stream.close()
            return

        if is_premium:
            print(
                f"[*] Sent Transfer for PREMIUM user {username} to {target_host}:{target_port}"
            )
            cookie_payload = build_auth_cookie(username, user_uuid, False)
            stream.write_packet(
                "store_cookie",
                "configuration",
                Encode.store_cookie("onemcserver:auth", cookie_payload),
            )
            stream.write_packet(
                "transfer", "configuration", Encode.transfer(target_host, target_port)
            )
            await stream.drain()
            stream.close()
            return

        # --- CONFIGURATION FOR CRACKED (LIMBO) ---
        stream.write_packet(
            "custom_payload", "configuration", Encode.brand("onemcserver")
        )
        schema_version = resolve_login_packet_version(stream.protocol_version)
        stream.write_packet(
            "select_known_packs",
            "configuration",
            Encode.select_known_packs(schema_version),
        )
        await stream.drain()

        # Wait for client's known_packs response, then use the client's own
        # reported core pack version as schema hint for registry/login data.
        known_packs_id = get_packet_id(
            stream.protocol_version, "configuration", "toServer", "select_known_packs"
        )
        known_packs_packet = None
        while True:
            packet = await stream.read_packet()
            pid, _ = Decode._read_varint(packet, 0)
            if known_packs_id is None or pid == known_packs_id:
                known_packs_packet = packet
                break

        client_core_version = parse_client_core_version_from_known_packs(
            known_packs_packet
        )
        if client_core_version:
            schema_version = resolve_login_packet_version(
                stream.protocol_version, client_core_version
            )
            print(
                f"[*] Client core version hint: {client_core_version} -> schema {schema_version}"
            )

        # Send Registries (Mandatory for 1.20.5+)
        resolved_version, lp_data = load_login_packet(
            stream.protocol_version, schema_version
        )
        print(
            f"[*] Using loginPacket schema {resolved_version} for protocol {stream.protocol_version}"
        )
        codec = lp_data.get("dimensionCodec", {})

        for reg_id, reg_data in codec.items():
            entries = reg_data.get("entries", [])
            print(f"[*] Syncing registry: {reg_id} with {len(entries)} entries")
            body = Encode.encode_string(reg_id)
            body += Encode.encode_varint(len(entries))
            for reg_entry in entries:
                body += Encode.encode_string(reg_entry["key"])
                if reg_entry.get("value"):
                    body += b"\x01" + Encode.encode_anonymous_nbt(reg_entry["value"])
                else:
                    body += b"\x00"
            stream.write_packet("registry_data", "configuration", body)

        # Configuration tags are required for dynamic registries in newer clients.
        tags_body = build_configuration_tags_packet(codec)
        stream.write_packet("tags", "configuration", tags_body)

        # Mirror a normal configuration bootstrap more closely by advertising
        # the vanilla feature flag set before finishing configuration.
        stream.write_packet(
            "feature_flags",
            "configuration",
            Encode.encode_varint(1) + Encode.encode_string("minecraft:vanilla"),
        )

        from mc_engine import AuthEngine

        signing_key_bytes = _signing_private_key.private_bytes(
            CryptoEncoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        engine = AuthEngine(
            stream,
            username,
            target_host,
            target_port,
            cache_col,
            signing_key_bytes,
            resolved_version,
        )
        await engine.enter_limbo()

    except Exception as e:
        if not isinstance(e, (asyncio.IncompleteReadError, ConnectionResetError)):
            import traceback

            traceback.print_exc()
    finally:
        stream.close()


async def main():
    _load_or_generate_keys()
    print(f"[*] Ed25519 Public Key: {_signing_public_key_hex}")
    await init_db()
    port = global_config.get("port", 25565)
    server = await asyncio.start_server(handle_client, "0.0.0.0", port)
    print(f"[*] Listening on {port}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
