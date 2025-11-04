import socket
import threading
from crypto_utils import encrypt_message, decrypt_message

def start_client():
    host = input("Enter target hostname or IP: ").strip()
    port = 5000

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host, port))
        print(f"[+] Connected to {host}:{port}")
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return

    # Receive encryption key from host
    key = client_socket.recv(4096)
    if not key:
        print("[-] No key received. Connection aborted.")
        client_socket.close()
        return

    print("[*] Secure channel established.\n")

    # Thread for receiving messages
    def receive():
        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    print("\n[-] Connection closed by server.")
                    break
                decrypted = decrypt_message(data, key)
                print(f"\n[Host]: {decrypted}")
            except:
                break

    threading.Thread(target=receive, daemon=True).start()

    # Main loop: send messages
    while True:
        try:
            msg = input("[You]: ")
            encrypted = encrypt_message(msg, key)
            client_socket.sendall(encrypted)
        except KeyboardInterrupt:
            print("\n[!] Closing connection.")
            client_socket.close()
            break
        except:
            print("[-] Connection lost.")
            break


if __name__ == "__main__":
    try:
        start_client()
    except Exception as e:
        print(f"[ERROR] {e}")
