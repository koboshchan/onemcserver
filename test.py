import socket
import select

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
                            hex_dump(data, "C -> S")
                            remote_sock.sendall(data)
                        else:
                            hex_dump(data, "S -> C")
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
