import struct, json


class Encode:
    @staticmethod
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

    @staticmethod
    def _create_raw(packet_id, data, compression=True):
        payload = Encode.encode_varint(packet_id) + data
        if compression:
            payload = Encode.encode_varint(0) + payload
        return Encode.encode_varint(len(payload)) + payload

    @staticmethod
    def transfer(host="server.kobosh.com", port=25565, compression=True):
        data = (
            Encode.encode_varint(len(host)) + host.encode() + Encode.encode_varint(port)
        )
        return Encode._create_raw(0x0B, data, compression=compression)

    @staticmethod
    def set_compression(threshold=256, compression=False):
        # The Set Compression packet (ID 0x03) needs to be framed correctly.
        # [Packet Length] [ID 0x03] [Threshold (VarInt)]
        data = Encode.encode_varint(0x03) + Encode.encode_varint(threshold)
        return Encode.encode_varint(len(data)) + data

    @staticmethod
    def status_response(json_data, compression=False):
        # The Status Response packet (ID 0x00)
        # Body: JSON String (prefixed by its length as a VarInt)
        json_str = json.dumps(json_data)
        data = Encode.encode_varint(len(json_str)) + json_str.encode()
        return Encode._create_raw(0x00, data, compression=compression)

    @staticmethod
    def brand(brand="Purpur", compression=True):
        data = Encode.encode_varint(len(brand)) + brand.encode()
        return Encode._create_raw(0x01, data, compression=compression)

    @staticmethod
    def select_known_packs(version, namespace="minecraft", id="core", compression=True):
        body = (
            b"\x01"
            + Encode.encode_varint(len(namespace))
            + namespace.encode()
            + Encode.encode_varint(len(id))
            + id.encode()
            + Encode.encode_varint(len(version))
            + version.encode()
        )
        return Encode._create_raw(0x0E, body, compression=compression)

    @staticmethod
    def disconnect(reason='"Disconnected"', compression=True):
        # 1. Minecraft expects Chat components to be JSON strings
        # Ensure the reason is wrapped in quotes if it's a plain message
        if not reason.startswith("{") and not reason.startswith('"'):
            reason = f'"{reason}"'

        # 2. Encode to UTF-8 bytes first
        reason_bytes = reason.encode("utf-8")

        # 3. Use the length of the BYTES for the VarInt
        data = Encode.encode_varint(len(reason_bytes)) + reason_bytes

        return Encode._create_raw(0x00, data, compression=compression)


class VersionBase:
    protocol_version = None

    def encode_varint(self, val):
        return Encode.encode_varint(val)

    def _create_raw(self, packet_id, data, compression=True):
        return Encode._create_raw(packet_id, data, compression=compression)

    def transfer(self, host="server.kobosh.com", port=25565, compression=True):
        data = self.encode_varint(len(host)) + host.encode() + self.encode_varint(port)
        return self._create_raw(0x0B, data, compression=compression)

    def set_compression(self, threshold=256, compression=False):
        # [Packet Length] [ID 0x03] [Threshold (VarInt)]
        data = self.encode_varint(0x03) + self.encode_varint(threshold)
        return self.encode_varint(len(data)) + data

    def login_success(
        self,
        uuid="ba096d9aed4a3689b7502eed340ad2cd",
        username="kobosh",
        compression=True,
    ):
        body = (
            bytes.fromhex(uuid)
            + self.encode_varint(len(username))
            + username.encode()
            + self.encode_varint(0)
        )
        return self._create_raw(0x02, body, compression=compression)

    def brand(self, brand="Purpur", compression=True):
        data = self.encode_varint(len(brand)) + brand.encode()
        return self._create_raw(0x01, data, compression=compression)

    def select_known_packs(
        self, version, namespace="minecraft", id="core", compression=True
    ):
        body = (
            b"\x01"
            + self.encode_varint(len(namespace))
            + namespace.encode()
            + self.encode_varint(len(id))
            + id.encode()
            + self.encode_varint(len(version))
            + version.encode()
        )
        return self._create_raw(0x0E, body, compression=compression)

    def disconnect(self, reason='"Disconnected"', compression=True):
        if not reason.startswith("{") and not reason.startswith('"'):
            reason = f'"{reason}"'
        reason_bytes = reason.encode("utf-8")
        data = self.encode_varint(len(reason_bytes)) + reason_bytes
        return self._create_raw(0x00, data, compression=compression)


class Version767(VersionBase):
    protocol_version = 767

    def login_success(
        self,
        uuid="ba096d9aed4a3689b7502eed340ad2cd",
        username="kobosh",
        compression=True,
        strict_error_handling=False,
    ):
        body = (
            bytes.fromhex(uuid)
            + self.encode_varint(len(username))
            + username.encode()
            + self.encode_varint(0)
            + (b"\x01" if strict_error_handling else b"\x00")
        )
        return self._create_raw(0x02, body, compression=compression)


class Version773(VersionBase):
    protocol_version = 773


def get_version_handler(protocol_version):
    # 767 and older use Login Success with strict_error_handling boolean.
    if protocol_version <= Version767.protocol_version:
        return Version767()
    return Version773()


class Decode:
    @staticmethod
    def _read_varint(data, offset):
        val = 0
        for i, byte in enumerate(data[offset:]):
            val |= (byte & 0x7F) << (7 * i)
            if not (byte & 0x80):
                return val, offset + i + 1
        return 0, offset

    @staticmethod
    def _read_string(data, offset):
        length, offset = Decode._read_varint(data, offset)
        string = data[offset : offset + length].decode("utf-8")
        return string, offset + length

    @staticmethod
    def handshake(data):
        offset = 0
        if len(data) < 10:  # Minimum handshake packet size
            raise ValueError(f"Handshake packet too short: {len(data)} bytes")

        length, offset = Decode._read_varint(data, offset)
        packet_id, offset = Decode._read_varint(data, offset)
        protocol_version, offset = Decode._read_varint(data, offset)
        address, offset = Decode._read_string(data, offset)

        # Ensure we have at least 2 bytes for port
        if offset + 2 > len(data):
            raise ValueError(
                f"Incomplete port data: need 2 bytes, have {len(data) - offset}"
            )

        port = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
        next_state, offset = Decode._read_varint(data, offset)
        return {
            "name": "handshake",
            "protocol_version": protocol_version,
            "address": address,
            "port": port,
            "next_state": next_state,
        }

    @staticmethod
    def login_start(data):
        if not data or len(data) < 3:
            return {"name": "login_start", "username": "unknown", "uuid": "00"}
        offset = 0
        length, offset = Decode._read_varint(data, offset)
        packet_id, offset = Decode._read_varint(data, offset)
        username, offset = Decode._read_string(data, offset)
        # Check if UUID exists in packet
        uuid = ""
        if offset + 16 <= len(data):
            uuid = data[offset : offset + 16].hex()
        return {"name": "login_start", "username": username, "uuid": uuid}

    @staticmethod
    def login_acknowledged(data):
        return {"name": "login_acknowledged"}

    @staticmethod
    def client_config(data):
        return {"name": "client_config", "data": data.hex()}
