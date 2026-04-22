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
    def encode_string(string):
        data = string.encode("utf-8")
        return Encode.encode_varint(len(data)) + data

    @staticmethod
    def encryption_request(public_key, verify_token, server_id=""):
        return (
            Encode.encode_string(server_id)
            + Encode.encode_varint(len(public_key))
            + public_key
            + Encode.encode_varint(len(verify_token))
            + verify_token
            + b"\x01"
        )

    @staticmethod
    def login_success(uuid_str, username, properties=[]):
        import uuid as uuid_lib

        uuid_bytes = uuid_lib.UUID(uuid_str).bytes
        props_data = Encode.encode_varint(len(properties))
        for prop in properties:
            props_data += Encode.encode_string(prop["name"])
            props_data += Encode.encode_string(prop["value"])
            if prop.get("signature"):
                props_data += b"\x01" + Encode.encode_string(prop["signature"])
            else:
                props_data += b"\x00"
        return uuid_bytes + Encode.encode_string(username) + props_data + b"\x00"

    @staticmethod
    def set_compression(threshold=256):
        return Encode.encode_varint(threshold)

    @staticmethod
    def transfer(host, port):
        return Encode.encode_string(host) + Encode.encode_varint(port)

    @staticmethod
    def store_cookie(identifier, value_bytes):
        return (
            Encode.encode_string(identifier)
            + Encode.encode_varint(len(value_bytes))
            + value_bytes
        )

    @staticmethod
    def brand(brand="onemcserver"):
        brand_data = Encode.encode_string(brand)
        return Encode.encode_string("minecraft:brand") + brand_data

    @staticmethod
    def select_known_packs(version):
        return (
            b"\x01"
            + Encode.encode_string("minecraft")
            + Encode.encode_string("core")
            + Encode.encode_string(version)
        )

    @staticmethod
    def disconnect(reason):
        if not (
            isinstance(reason, str)
            and (reason.startswith("{") or reason.startswith('"'))
        ):
            reason = json.dumps({"text": str(reason)})
        return Encode.encode_string(reason)

    @staticmethod
    def encode_chat_nbt(text):
        """Encodes a simple text message as a 1.20.5+ NBT chat component."""
        typed_obj = {
            "type": "compound",
            "value": {"text": {"type": "string", "value": text}},
        }
        return Encode.encode_anonymous_nbt(typed_obj)

    @staticmethod
    def status_response(json_data):
        json_str = json.dumps(json_data)
        data = Encode.encode_string(json_str)
        body = Encode.encode_varint(0x00) + data
        return Encode.encode_varint(len(body)) + body

    @staticmethod
    def _encode_nbt_value(t, val):
        t = t.lower()
        if t == "compound":
            res = b""
            if not isinstance(val, dict):
                return b"\x00"
            for k, v in val.items():
                if not isinstance(v, dict) or "type" not in v:
                    continue
                type_name = v["type"]
                if isinstance(type_name, dict):  # Handle nested type definitions if any
                    continue
                res += Encode.get_nbt_type_id(type_name)
                res += struct.pack(">H", len(k)) + k.encode("utf-8")
                res += Encode._encode_nbt_value(type_name, v.get("value"))
            return res + b"\x00"
        elif t == "list":
            l_type = val["type"]
            res = Encode.get_nbt_type_id(l_type)
            res += struct.pack(">i", len(val["value"]))
            for item in val["value"]:
                res += Encode._encode_nbt_value(l_type, item)
            return res
        elif t == "string":
            data = str(val).encode("utf-8")
            return struct.pack(">H", len(data)) + data
        elif t == "int":
            return struct.pack(">i", int(val))
        elif t == "byte":
            return struct.pack(">b", int(val))
        elif t == "short":
            return struct.pack(">h", int(val))
        elif t == "long":
            if isinstance(val, list) and len(val) == 2:
                # Combine [high, low] into a single 64-bit integer
                combined = (int(val[0]) << 32) | (int(val[1]) & 0xFFFFFFFF)
                return struct.pack(">q", combined)
            return struct.pack(">q", int(val))
        elif t == "float":
            return struct.pack(">f", float(val))
        elif t == "double":
            return struct.pack(">d", float(val))
        elif t in ("long_array", "longarray"):
            res = struct.pack(">i", len(val))
            for item in val:
                res += struct.pack(">q", int(item))
            return res
        elif t in ("int_array", "intarray"):
            res = struct.pack(">i", len(val))
            for item in val:
                res += struct.pack(">i", int(item))
            return res
        elif t in ("byte_array", "bytearray"):
            res = struct.pack(">i", len(val))
            res += bytes(val)
            return res
        return b""

    @staticmethod
    def encode_nbt(typed_obj, name=""):
        """Encodes as Tag ID (10) + Name Length + Name + Payload"""
        return (
            b"\x0a"
            + struct.pack(">H", len(name))
            + name.encode("utf-8")
            + Encode._encode_nbt_value("compound", typed_obj["value"])
        )

    @staticmethod
    def encode_anonymous_nbt(typed_obj):
        """Encodes as Tag ID (10) + Payload (No name)"""
        # 1.20.2+ Network NBT for compounds is often Tag ID 10 + Payload (no name).
        # We use standard named NBT with empty name as fallback if the above fails.
        return b"\x0a" + Encode._encode_nbt_value("compound", typed_obj["value"])

    @staticmethod
    def get_nbt_type_id(t):
        if not isinstance(t, str):
            return b"\x00"
        t = t.lower()
        types = {
            "end": b"\x00",
            "byte": b"\x01",
            "short": b"\x02",
            "int": b"\x03",
            "long": b"\x04",
            "float": b"\x05",
            "double": b"\x06",
            "byte_array": b"\x07",
            "bytearray": b"\x07",
            "string": b"\x08",
            "list": b"\x09",
            "compound": b"\x0a",
            "int_array": b"\x0b",
            "intarray": b"\x0b",
            "long_array": b"\x0c",
            "longarray": b"\x0c",
        }
        return types.get(t, b"\x00")


class Decode:
    @staticmethod
    def _read_varint(data, offset):
        val = 0
        for i in range(5):
            if offset + i >= len(data):
                return 0, offset
            byte = data[offset + i]
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
        _, offset = Decode._read_varint(data, offset)  # packet_id
        protocol_version, offset = Decode._read_varint(data, offset)
        address, offset = Decode._read_string(data, offset)
        port = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
        next_state, offset = Decode._read_varint(data, offset)
        return {
            "protocol_version": protocol_version,
            "address": address,
            "port": port,
            "next_state": next_state,
        }

    @staticmethod
    def login_start(data):
        offset = 0
        _, offset = Decode._read_varint(data, offset)
        username, offset = Decode._read_string(data, offset)
        player_uuid = None
        if offset + 16 <= len(data):
            import uuid

            player_uuid = str(uuid.UUID(bytes=data[offset : offset + 16]))
        return {"username": username, "uuid": player_uuid}

    @staticmethod
    def encryption_response(data):
        offset = 0
        _, offset = Decode._read_varint(data, offset)
        shared_secret_len, offset = Decode._read_varint(data, offset)
        shared_secret = data[offset : offset + shared_secret_len]
        offset += shared_secret_len
        verify_token_len, offset = Decode._read_varint(data, offset)
        verify_token = data[offset : offset + verify_token_len]
        return {
            "shared_secret": shared_secret,
            "verify_token": verify_token,
        }
