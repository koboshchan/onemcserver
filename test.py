import socket
import select
import zlib

# Configuration
LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 25564
REMOTE_HOST = "127.0.0.1"
REMOTE_PORT = 25565


def hex_dump(data, prefix):
    """Prints data in a readable hex format."""
    # Blue for Client -> Server, Green for Server -> Client
    color = "\033[94m" if "C->S" in prefix else "\033[92m"
    reset = "\033[0m"
    print(f"{color}{prefix} ({len(data)} bytes): {data.hex(' ')}{reset}\n")


def read_varint(data, offset=0):
    val = 0
    for i in range(5):
        if offset >= len(data):
            return None, offset
        b = data[offset]
        offset += 1
        val |= (b & 0x7F) << (i * 7)
        if (b & 0x80) == 0:
            return val, offset
    return None, offset


class PacketParser:
    def __init__(self, prefix):
        self.buffer = b""
        self.prefix = prefix

    def add_data(self, data):
        self.buffer += data
        while True:
            packet_length, offset = read_varint(self.buffer, 0)
            if packet_length is None:
                break
            if len(self.buffer) < offset + packet_length:
                break

            packet_data = self.buffer[offset : offset + packet_length]
            self.buffer = self.buffer[offset + packet_length :]

            self.dump_packet(packet_data)

    def dump_packet(self, packet_data):
        try:
            data_length, data_offset = read_varint(packet_data, 0)
            if data_length is not None and data_length > 0:
                compressed_payload = packet_data[data_offset:]
                uncompressed_data = zlib.decompress(compressed_payload)
                if len(uncompressed_data) == data_length:
                    hex_dump(uncompressed_data, f"{self.prefix} (Uncompressed)")
                    return
        except Exception:
            pass

        hex_dump(packet_data, self.prefix)


def start_proxy():
    # 1. Setup the Listening Socket (Local)
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((LOCAL_HOST, LOCAL_PORT))
    server_sock.listen(5)
    print(f"[*] Sniffer listening on {LOCAL_HOST}:{LOCAL_PORT}")

    try:
        while True:
            client_conn, addr = server_sock.accept()
            print(f"[*] New connection from {addr}")

            # 2. Setup the Upstream Socket (To real server)
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                remote_sock.connect((REMOTE_HOST, REMOTE_PORT))
            except Exception as e:
                print(f"[!] Failed to connect to remote: {e}")
                client_conn.close()
                continue

            # 3. Forwarding Loop
            sockets = [client_conn, remote_sock]
            c2s_parser = PacketParser("C -> S")
            s2c_parser = PacketParser("S -> C")
            running = True
            while running:
                # Wait for data on either socket
                readable, _, _ = select.select(sockets, [], [])

                for s in readable:
                    try:
                        data = s.recv(4096)
                        if not data:
                            running = False
                            break

                        # Forwarding
                        if s is client_conn:
                            c2s_parser.add_data(data)
                            remote_sock.sendall(data)
                        else:
                            s2c_parser.add_data(data)
                            client_conn.sendall(data)
                    except (ConnectionResetError, BrokenPipeError, OSError):
                        running = False
                        break

            print("[*] Connection closed.")
            client_conn.close()
            remote_sock.close()

    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    start_proxy()
