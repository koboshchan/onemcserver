import struct


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
        return (
            Encode.encode_varint(1)
            + Encode.encode_varint(0x03)
            + Encode.encode_varint(threshold)
        )

    @staticmethod
    def login_success(
        uuid="ba096d9aed4a3689b7502eed340ad2cd", username="kobosh", compression=True
    ):
        body = (
            bytes.fromhex(uuid)
            + Encode.encode_varint(len(username))
            + username.encode()
            + b"\x00"
        )
        return Encode._create_raw(0x02, body, compression=compression)

    @staticmethod
    def brand(brand="Purpur", compression=True):
        data = Encode.encode_varint(len(brand)) + brand.encode()
        return Encode._create_raw(0x01, data, compression=compression)

    @staticmethod
    def select_known_packs(version,namespace="minecraft",id="core",compression=True):
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
        length, offset = Decode._read_varint(data, offset)
        packet_id, offset = Decode._read_varint(data, offset)
        protocol_version, offset = Decode._read_varint(data, offset)
        address, offset = Decode._read_string(data, offset)
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
        offset = 0
        length, offset = Decode._read_varint(data, offset)
        packet_id, offset = Decode._read_varint(data, offset)
        username, offset = Decode._read_string(data, offset)
        uuid = data[offset : offset + 16].hex()
        return {"name": "login_start", "username": username, "uuid": uuid}

    @staticmethod
    def login_acknowledged(data):
        return {"name": "login_acknowledged"}

    @staticmethod
    def client_config(data):
        return {"name": "client_config", "data": data.hex()}
