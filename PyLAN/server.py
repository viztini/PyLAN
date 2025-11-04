import socket
import threading
from crypto_utils import generate_key, encrypt_message, decrypt_message

# Configuration
HOST = socket.gethostbyname(socket.gethostname())
PORT = 5000

def handle_client(conn, addr, key):
    print(f"[+] Connection established with {addr}")
    print("[*] Type messages below. Press Ctrl+C to quit.\n")

    # Thread for receiving messages
    def receive():
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    print("\n[-] Connection closed by client.")
                    break
                decrypted = decrypt_message(data, key)
                print(f"\n[Client]: {decrypted}")
            except:
                break

    threading.Thread(target=receive, daemon=True).start()

    # Main loop: send messages
    while True:
        try:
            msg = input("[You]: ")
            encrypted = encrypt_message(msg, key)
            conn.sendall(encrypted)
        except KeyboardInterrupt:
            print("\n[!] Closing connection.")
            conn.close()
            break
        except:
            print("[-] Connection lost.")
            break


def start_server():
    print(f"[*] Starting server on {HOST}:{PORT}...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"[+] Listening on {HOST}:{PORT}\n")

    conn, addr = server_socket.accept()
    print(f"[!] Incoming connection from {addr}")
    choice = input("Approve connection? (y/n): ").strip().lower()

    if choice != 'y':
        print("[-] Connection denied.")
        conn.close()
        return

    # Generate encryption key and send to client
    key = generate_key()
    conn.sendall(key)

    handle_client(conn, addr, key)


if __name__ == "__main__":
    try:
        start_server()
    except Exception as e:
        print(f"[ERROR] {e}")
