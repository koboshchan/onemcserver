import asyncio
import json
import struct
import os
import uuid
from datetime import datetime, timezone
from mc_packets import Encode, Decode
from mc_protocol import loader, get_packet_id


class AuthEngine:
    def __init__(self, stream, username, target_host, target_port, cache_col):
        self.stream = stream
        self.username = username
        self.target_host = target_host
        self.target_port = target_port
        self.authenticated = False
        self.proto_ver = stream.protocol_version
        self.cache_col = cache_col

    async def enter_limbo(self):
        """Transition from CONFIGURATION to PLAY and host the void world."""
        # 1. Finish Configuration
        self.stream.write_packet("finish_configuration", "configuration", b"")
        await self.stream.drain()

        # 2. Wait for Finish Configuration
        finish_id = get_packet_id(
            self.proto_ver, "configuration", "toServer", "finish_configuration"
        )
        while True:
            packet = await self.stream.read_packet()
            pid, _ = Decode._read_varint(packet, 0)
            if pid == finish_id:
                break

        # NOW IN PLAY STATE
        print(f"[*] {self.username} entered Auth Limbo (PLAY state)")

        # 4. Player Info (Mandatory for spawning)
        user_uuid_str = str(
            uuid.uuid3(uuid.NAMESPACE_DNS, f"OfflinePlayer:{self.username}")
        )
        user_uuid = uuid.UUID(user_uuid_str)

        info_body = b"\x09"
        info_body += Encode.encode_varint(1)  # Player Count
        info_body += user_uuid.bytes
        info_body += Encode.encode_string(self.username)
        info_body += Encode.encode_varint(0)  # Properties
        info_body += Encode.encode_varint(1)  # Listed = true
        self.stream.write_packet("player_info", "play", info_body)

        # 5. Set Player Abilities
        self.stream.write_packet(
            "abilities", "play", b"\x06" + struct.pack(">ff", 0.05, 0.1)
        )

        # 6. Send a minimal empty chunk
        chunk_data = self.create_empty_chunk()
        self.stream.write_packet("map_chunk", "play", chunk_data)

        # 7. Set View Position
        self.stream.write_packet(
            "update_view_position",
            "play",
            Encode.encode_varint(0) + Encode.encode_varint(0),
        )

        # 8. Synchronize Position
        pos_body = struct.pack(
            ">dddffB", 0.0, 100.0, 0.0, 0.0, 0.0, 0
        ) + Encode.encode_varint(1)
        self.stream.write_packet("position", "play", pos_body)

        # 9. Prompt for password
        await self.send_message("§6[onemcserver] §eWelcome! This is a cracked account.")

        # Drain any pending packets (like MOTD) before starting auth
        await self._drain_pending_packets()

        user_record = await self.cache_col.find_one(
            {"name": self.username, "password": {"$exists": True}}
        )
        if user_record:
            await self.send_message("§ePlease login: §b/login <password>")
        else:
            await self.send_message("§ePlease register: §b/register <password>")

        # 10. Wait for auth commands (only for authenticated/registered players)
        await self.handle_commands()

        # 11. After authenticated, transfer
        if self.authenticated:
            await self.send_message("§aAuthenticated! Transferring...")
            await asyncio.sleep(1)
            self.stream.write_packet(
                "transfer", "play", Encode.transfer(self.target_host, self.target_port)
            )
            await self.stream.drain()

    async def _drain_pending_packets(self):
        """Drain any pending packets (like MOTD) before auth."""
        try:
            while True:
                packet = await asyncio.wait_for(self.stream.read_packet(), timeout=0.5)
                # Check if this is a login success packet - if so, client is already logged in
                if len(packet) >= 1:
                    pid, offset = Decode._read_varint(packet, 0)
                    # If it looks like a login success (0x02 or 0x01 in login state)
                    if pid == 0x02:  # Login success
                        print(
                            f"[*] Pending login success packet from server, client already authenticated"
                        )
                        self.authenticated = True
                        return
        except (asyncio.TimeoutError, ConnectionError):
            pass

    def create_login_packet(self):
        """Builds a compliant Login (Play) packet using minecraft-data."""
        version_str = loader.proto_to_version.get(self.proto_ver, "1.21.1")
        lp_path = os.path.join(
            "minecraft-data-repo", "data", "pc", version_str, "loginPacket.json"
        )
        if not os.path.exists(lp_path):
            lp_path = os.path.join(
                "minecraft-data-repo", "data", "pc", "1.21.1", "loginPacket.json"
            )

        lp = json.load(open(lp_path))

        body = struct.pack(">i?", int(lp["entityId"]), bool(lp["isHardcore"]))
        body += Encode.encode_varint(len(lp["worldNames"]))
        for name in lp["worldNames"]:
            body += Encode.encode_string(name)

        body += Encode.encode_varint(int(lp["maxPlayers"]))
        body += Encode.encode_varint(int(lp["viewDistance"]))
        body += Encode.encode_varint(int(lp["simulationDistance"]))
        body += struct.pack(
            ">???",
            bool(lp["reducedDebugInfo"]),
            bool(lp["enableRespawnScreen"]),
            bool(lp["doLimitedCrafting"]),
        )

        ws = lp["worldState"]
        body += Encode.encode_varint(int(ws["dimension"]))
        body += Encode.encode_string(ws["name"])

        # Seed
        seed_high, seed_low = int(ws["hashedSeed"][0]), int(ws["hashedSeed"][1])
        body += struct.pack(">q", (seed_high << 32) | (seed_low & 0xFFFFFFFF))

        body += b"\x03"  # Spectator
        body += struct.pack(">B", int(ws["previousGamemode"]))  # Unsigned Byte (255)
        body += struct.pack(">??", bool(ws["isDebug"]), bool(ws["isFlat"]))
        body += b"\x00"  # Death location not present
        body += Encode.encode_varint(int(ws["portalCooldown"]))
        body += struct.pack(">?", bool(lp["enforcesSecureChat"]))

        return body

    def create_empty_chunk(self):
        body = struct.pack(">ii", 0, 0)
        heightmap = {
            "type": "compound",
            "value": {"MOTION_BLOCKING": {"type": "long_array", "value": [0] * 37}},
        }
        body += Encode.encode_anonymous_nbt(heightmap)
        body += Encode.encode_varint(0)  # Data Size
        body += Encode.encode_varint(0)  # Block Entities

        # Light Data
        body += Encode.encode_varint(0)  # Sky Light Mask
        body += Encode.encode_varint(0)  # Block Light Mask
        body += Encode.encode_varint(0)  # Empty Sky Light Mask
        body += Encode.encode_varint(0)  # Empty Block Light Mask
        body += Encode.encode_varint(0)  # Sky Light Array Count
        body += Encode.encode_varint(0)  # Block Light Array Count
        return body

    async def send_message(self, text):
        data = Encode.encode_chat_nbt(text) + b"\x00"
        self.stream.write_packet("system_chat", "play", data)
        await self.stream.drain()

    async def handle_commands(self):
        while not self.authenticated:
            try:
                packet = await self.stream.read_packet()
                pid, offset = Decode._read_varint(packet, 0)
                payload = packet[offset:]

                cmd_id = get_packet_id(
                    self.proto_ver, "play", "toServer", "chat_command"
                )
                cmd_signed_id = get_packet_id(
                    self.proto_ver, "play", "toServer", "chat_command_signed"
                )
                msg_id = get_packet_id(
                    self.proto_ver, "play", "toServer", "chat_message"
                )

                if pid == cmd_id or pid == cmd_signed_id:
                    command, _ = Decode._read_string(payload, 0)
                    parts = command.split(" ")
                    cmd = parts[0]
                    if cmd == "login" and len(parts) > 1:
                        if await self.cache_col.find_one(
                            {"name": self.username, "password": parts[1]}
                        ):
                            self.authenticated = True
                        else:
                            await self.send_message("§cIncorrect password!")
                    elif cmd == "register" and len(parts) > 1:
                        if await self.cache_col.find_one(
                            {"name": self.username, "password": {"$exists": True}}
                        ):
                            await self.send_message("§cAlready registered!")
                        else:
                            await self.cache_col.update_one(
                                {"name": self.username},
                                {
                                    "$set": {
                                        "password": parts[1],
                                        "created": datetime.now(timezone.utc),
                                    }
                                },
                                upsert=True,
                            )
                            self.authenticated = True
                    else:
                        await self.send_message(
                            "§cUse /login <pass> or /register <pass>"
                        )
                elif pid == msg_id:
                    await self.send_message("§cPlease login first.")
            except:
                break

        if self.authenticated:
            await self.send_message("§aAuthenticated! Transferring...")
            await asyncio.sleep(1)
            self.stream.write_packet(
                "transfer", "play", Encode.transfer(self.target_host, self.target_port)
            )
            await self.stream.drain()
