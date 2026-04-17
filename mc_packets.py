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
            + b"\x01"  # Should authenticate (1.20.5+)
        )

    @staticmethod
    def login_success(uuid_str, username, properties=[]):
        import uuid as uuid_lib

        uuid_bytes = uuid_lib.UUID(uuid_str).bytes

        # Encode properties array
        props_data = Encode.encode_varint(len(properties))
        for prop in properties:
            name = prop["name"]
            value = prop["value"]
            signature = prop.get("signature")

            props_data += Encode.encode_string(name)
            props_data += Encode.encode_string(value)
            if signature:
                props_data += b"\x01" + Encode.encode_string(signature)
            else:
                props_data += b"\x00"

        return (
            uuid_bytes
            + Encode.encode_string(username)
            + props_data
            + b"\x00"  # strictErrorHandling - Set to false for better compatibility
        )

    @staticmethod
    def set_compression(threshold=256):
        return Encode.encode_varint(threshold)

    @staticmethod
    def transfer(host, port):
        return Encode.encode_string(host) + Encode.encode_varint(port)

    @staticmethod
    def brand(brand="onemcserver"):
        return Encode.encode_string(brand)

    @staticmethod
    def select_known_packs(version):
        return (
            b"\x01"  # Array length 1
            + Encode.encode_string("minecraft")
            + Encode.encode_string("core")
            + Encode.encode_string(version)
        )

    @staticmethod
    def disconnect(reason):
        if not (reason.startswith("{") or reason.startswith('"')):
            reason = json.dumps({"text": reason})
        return Encode.encode_string(reason)

    @staticmethod
    def status_response(json_data):
        json_str = json.dumps(json_data)
        data = Encode.encode_string(json_str)
        body = Encode.encode_varint(0x00) + data
        return Encode.encode_varint(len(body)) + body


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
        packet_id, offset = Decode._read_varint(data, offset)
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
        packet_id, offset = Decode._read_varint(data, offset)
        username, offset = Decode._read_string(data, offset)
        player_uuid = None
        if offset + 16 <= len(data):
            import uuid

            player_uuid = str(uuid.UUID(bytes=data[offset : offset + 16]))
        return {"username": username, "uuid": player_uuid}

    @staticmethod
    def encryption_response(data):
        offset = 0
        packet_id, offset = Decode._read_varint(data, offset)
        shared_secret_len, offset = Decode._read_varint(data, offset)
        shared_secret = data[offset : offset + shared_secret_len]
        offset += shared_secret_len
        verify_token_len, offset = Decode._read_varint(data, offset)
        verify_token = data[offset : offset + verify_token_len]
        return {
            "shared_secret": shared_secret,
            "verify_token": verify_token,
        }
