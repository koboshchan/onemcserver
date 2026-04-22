import asyncio
import base64
import contextlib
import json
import struct
import os
import time
import uuid
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding as CryptoEncoding,
    PrivateFormat,
    NoEncryption,
)
from mc_packets import Encode, Decode
from mc_protocol import get_packet_id, load_login_packet


class AuthEngine:
    def __init__(
        self,
        stream,
        username,
        target_host,
        target_port,
        cache_col,
        signing_key_bytes=None,
        schema_version=None,
    ):
        self.stream = stream
        self.username = username
        self.target_host = target_host
        self.target_port = target_port
        self.authenticated = False
        self.proto_ver = stream.protocol_version
        self.cache_col = cache_col
        self.signing_key_bytes = signing_key_bytes
        self.schema_version = schema_version
        self._keepalive_task = None
        self.limbo_chunk_radius = 2
        self.limbo_view_distance = 2

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
        print(f"[*] {self.username} entered PLAY state")

        # 3. Login packet (first packet in play state)
        self.stream.write_packet("login", "play", self.create_login_packet())

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

        # 6. Set world view center and radius before streaming chunks.
        self.stream.write_packet(
            "update_view_position",
            "play",
            Encode.encode_varint(0) + Encode.encode_varint(0),
        )

        # Keep the world-view settings aligned with login to avoid client-side stall.
        self.stream.write_packet(
            "update_view_distance",
            "play",
            Encode.encode_varint(self.limbo_view_distance),
        )
        self.stream.write_packet(
            "simulation_distance",
            "play",
            Encode.encode_varint(self.limbo_view_distance),
        )

        # 7. Send empty chunks around spawn for limbo world warm-up.
        # 1.20.2+ might require chunk batching
        chunk_batch_start_id = get_packet_id(
            self.proto_ver, "play", "toClient", "chunk_batch_start"
        )
        chunk_batch_finished_id = get_packet_id(
            self.proto_ver, "play", "toClient", "chunk_batch_finished"
        )

        if chunk_batch_start_id is not None:
            self.stream.write_packet("chunk_batch_start", "play", b"")

        actual_radius = self.limbo_chunk_radius + 1
        chunk_count = (actual_radius * 2 + 1) ** 2
        
        # Send chunks in spiral order (center outward) for faster terrain rendering
        def spiral_coords(radius):
            """Generate chunk coordinates in spiral pattern from center outward"""
            yield (0, 0)  # Center first
            for layer in range(1, radius + 1):
                # Right edge going up
                for z in range(-layer + 1, layer + 1):
                    yield (layer, z)
                # Top edge going left
                for x in range(layer - 1, -layer - 1, -1):
                    yield (x, layer)
                # Left edge going down
                for z in range(layer - 1, -layer - 1, -1):
                    yield (-layer, z)
                # Bottom edge going right
                for x in range(-layer + 1, layer):
                    yield (x, -layer)
        
        for cx, cz in spiral_coords(actual_radius):
            chunk_data = self.create_empty_chunk(cx, cz)
            self.stream.write_packet("map_chunk", "play", chunk_data)

        if chunk_batch_finished_id is not None:
            self.stream.write_packet(
                "chunk_batch_finished", "play", Encode.encode_varint(chunk_count)
            )

        # 7.5 Set Default Spawn Position
        # Position X, Y, Z encoded as long: ((x & 0x3FFFFFF) << 38) | ((z & 0x3FFFFFF) << 12) | (y & 0xFFF)
        x, y, z = 0, 100, 0
        pos_long = ((x & 0x3FFFFFF) << 38) | ((z & 0x3FFFFFF) << 12) | (y & 0xFFF)
        spawn_body = struct.pack(">qf", pos_long, 0.0)  # Angle 0.0
        spawn_id = get_packet_id(self.proto_ver, "play", "toClient", "spawn_position")
        if spawn_id is not None:
            self.stream.write_packet("spawn_position", "play", spawn_body)

        # 8. Synchronize Position
        pos_body = struct.pack(
            ">dddffB", 0.0, 100.0, 0.0, 0.0, 0.0, 0
        ) + Encode.encode_varint(1)
        self.stream.write_packet("position", "play", pos_body)

        # 8.25 Real servers usually send at least baseline entity metadata and
        # attributes for the local player very early in PLAY state.
        self.stream.write_packet(
            "entity_metadata", "play", self.create_player_metadata(1)
        )
        self.stream.write_packet(
            "entity_update_attributes", "play", self.create_player_attributes(1)
        )

        # 8.5 Baseline player state packets commonly sent at join.
        self.stream.write_packet(
            "update_health",
            "play",
            struct.pack(">f", 20.0) + Encode.encode_varint(20) + struct.pack(">f", 5.0),
        )
        self.stream.write_packet("experience", "play", struct.pack(">f", 0.0) + Encode.encode_varint(0) + Encode.encode_varint(0))
        self.stream.write_packet("held_item_slot", "play", struct.pack(">b", 0))
        self.stream.write_packet("update_time", "play", struct.pack(">qq", 0, 6000))
        self.stream.write_packet("server_data", "play", self.create_server_data())
        self.stream.write_packet("declare_recipes", "play", self.create_empty_recipes())

        # Flush the initial world bootstrap and wait for the client to accept the
        # first teleport before entering the auth/chat phase. In 1.21.1 this is
        # one of the key signals that the client is done with the loading screen.
        await self.stream.drain()
        await self.await_initial_teleport_confirm(1)

        # 9. Prompt for password
        await self.send_message("§6[onemcserver] §eWelcome! This is a cracked account.")

        user_record = await self.cache_col.find_one(
            {"name": self.username, "password": {"$exists": True}}
        )
        if user_record:
            await self.send_message("§ePlease login: §b/login <password>")
        else:
            await self.send_message("§ePlease register: §b/register <password>")

        # 10. Keep connection alive while waiting for auth commands.
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())
        try:
            await self.handle_commands()
        finally:
            if self._keepalive_task:
                self._keepalive_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self._keepalive_task
                self._keepalive_task = None

    async def _keepalive_loop(self):
        while True:
            # Mojang uses i64 keepalive ids; monotonic ms works for limbo sessions.
            keepalive_id = int(time.time() * 1000)
            self.stream.write_packet("keep_alive", "play", struct.pack(">q", keepalive_id))
            await self.stream.drain()
            await asyncio.sleep(10)

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

    async def await_initial_teleport_confirm(self, teleport_id):
        teleport_confirm_id = get_packet_id(
            self.proto_ver, "play", "toServer", "teleport_confirm"
        )
        if teleport_confirm_id is None:
            return

        deadline = time.time() + 5.0
        while time.time() < deadline:
            timeout = max(0.1, deadline - time.time())
            try:
                packet = await asyncio.wait_for(self.stream.read_packet(), timeout=timeout)
            except asyncio.TimeoutError:
                break

            pid, offset = Decode._read_varint(packet, 0)
            if pid != teleport_confirm_id:
                continue

            received_teleport_id, _ = Decode._read_varint(packet, offset)
            if received_teleport_id == teleport_id:
                print(f"[*] Received initial teleport confirm from {self.username}")
                return

        print(f"[!] Timed out waiting for initial teleport confirm from {self.username}")

    def create_login_packet(self):
        """Builds a compliant Login (Play) packet using minecraft-data."""
        resolved_version, lp = load_login_packet(self.proto_ver, self.schema_version)
        print(
            f"[*] Limbo login packet schema {resolved_version} for protocol {self.proto_ver}"
        )

        body = struct.pack(">i?", int(lp["entityId"]), bool(lp["isHardcore"]))
        body += Encode.encode_varint(len(lp["worldNames"]))
        for name in lp["worldNames"]:
            body += Encode.encode_string(name)

        body += Encode.encode_varint(int(lp["maxPlayers"]))
        body += Encode.encode_varint(self.limbo_view_distance)  # viewDistance
        body += Encode.encode_varint(self.limbo_view_distance)  # simulationDistance
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

    def create_empty_chunk(self, cx, cz):
        body = struct.pack(">ii", cx, cz)
        heightmap = {
            "type": "compound",
            "value": {"MOTION_BLOCKING": {"type": "long_array", "value": [0] * 37}},
        }
        body += Encode.encode_anonymous_nbt(heightmap)

        # In 1.21.1, the world height is 384 (24 sections)
        # Each section: block_count(short) + block_states + biomes
        section = struct.pack(">h", 0)  # block count
        # Paletted container (single-valued) still includes an empty data-array length.
        section += (
            b"\x00" + Encode.encode_varint(0) + Encode.encode_varint(0)
        )  # block states (bpe=0, value=0, data array len=0)
        section += (
            b"\x00" + Encode.encode_varint(0) + Encode.encode_varint(0)
        )  # biomes (bpe=0, value=0, data array len=0)

        chunk_data = section * 24

        body += Encode.encode_varint(len(chunk_data))  # Data Size
        body += chunk_data
        body += Encode.encode_varint(0)  # Block Entities

        # Light Data bitsets cover chunk sections + 2 (top/bottom), so 26 bits for 384 world height.
        empty_light_mask = (1 << 26) - 1
        body += Encode.encode_varint(0)  # Sky Light Mask
        body += Encode.encode_varint(0)  # Block Light Mask
        body += Encode.encode_varint(1) + struct.pack(">q", empty_light_mask)  # Empty Sky Light Mask
        body += Encode.encode_varint(1) + struct.pack(">q", empty_light_mask)  # Empty Block Light Mask
        body += Encode.encode_varint(0)  # Sky Light Array Count
        body += Encode.encode_varint(0)  # Block Light Array Count
        return body

    def create_player_metadata(self, entity_id):
        body = Encode.encode_varint(entity_id)
        # Empty metadata list, terminated by 0xFF.
        body += b"\xff"
        return body

    def create_player_attributes(self, entity_id):
        body = Encode.encode_varint(entity_id)
        attributes = [
            (16, 20.0),  # generic.max_health
            (17, 0.10000000149011612),  # generic.movement_speed
            (9, 0.05),  # generic.flying_speed
        ]
        body += Encode.encode_varint(len(attributes))
        for key, value in attributes:
            body += Encode.encode_varint(key)
            body += struct.pack(">d", value)
            body += Encode.encode_varint(0)  # No modifiers
        return body

    def create_server_data(self):
        return Encode.encode_chat_nbt("koboshcrack - New World") + b"\x00"

    def create_empty_recipes(self):
        return Encode.encode_varint(0)

    def create_empty_tags(self):
        return Encode.encode_varint(0)

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
                keep_alive_id = get_packet_id(
                    self.proto_ver, "play", "toServer", "keep_alive"
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
                elif pid == keep_alive_id:
                    # Keepalive response; no further action needed for limbo auth flow.
                    continue
            except:
                break

        if self.authenticated:
            await self.send_message("§aAuthenticated! Transferring...")
            await asyncio.sleep(1)
            # Build and send signed auth cookie before transfer
            if self.signing_key_bytes:
                user_uuid_str = str(
                    uuid.uuid3(uuid.NAMESPACE_DNS, f"OfflinePlayer:{self.username}")
                )
                payload = json.dumps(
                    {
                        "username": self.username,
                        "uuid": user_uuid_str,
                        "cracked": True,
                        "time": int(time.time()),
                    },
                    separators=(",", ":"),
                ).encode("utf-8")
                private_key = Ed25519PrivateKey.from_private_bytes(self.signing_key_bytes)
                signature = private_key.sign(payload)
                cookie_value = payload + signature.hex().encode("ascii")
                self.stream.write_packet(
                    "store_cookie",
                    "play",
                    Encode.store_cookie("onemcserver:auth", cookie_value),
                )
            self.stream.write_packet(
                "transfer", "play", Encode.transfer(self.target_host, self.target_port)
            )
            await self.stream.drain()
