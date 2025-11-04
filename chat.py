#!/usr/bin/env python3
"""
chat.py — simple peer-to-peer LAN CLI chat with allow/deny on incoming connections.

Usage:
    python chat.py                 # interactive mode
    python chat.py --port 5050     # choose custom listening port
    python chat.py --no-server     # run only client connect (advanced)
    python chat.py --encrypt       # enable optional Fernet encryption (requires 'cryptography')

Notes:
 - Works on LAN. If machines are on different networks you need port-forwarding or a relay.
 - On first run Windows may prompt to allow Python through Firewall.
"""
import socket
import threading
import argparse
import sys
import queue
import time
import datetime
import traceback

# Optional encryption: try importing cryptography only if user enables it.
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

# --------------------
# Configuration / utils
# --------------------
DEFAULT_PORT = 5050
RECV_BUF = 4096
CONN_TIMEOUT = 10.0  # seconds for connect attempt
ENCODING = 'utf-8'

def now_stamp():
    return datetime.datetime.now().strftime('%H:%M:%S')

def print_info(*args, **kwargs):
    print("[*]", *args, **kwargs)

def print_err(*args, **kwargs):
    print("[!]", *args, **kwargs, file=sys.stderr)

# --------------------
# Networking primitives
# --------------------
class PeerServer(threading.Thread):
    """
    Thread that listens for incoming connections.
    When a connection arrives, it calls 'on_connection(conn, addr)' callback.
    """
    def __init__(self, host='', port=DEFAULT_PORT, on_connection=None, backlog=5):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.on_connection = on_connection
        self.backlog = backlog
        self._sock = None
        self._stop_event = threading.Event()

    def run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(self.backlog)
            self._sock = s
            print_info(f"Listening on {self._local_addrs()}:{self.port} (ctrl-c to quit)")
            while not self._stop_event.is_set():
                try:
                    s.settimeout(1.0)  # loop periodically to check stop flag
                    conn, addr = s.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                # For each incoming connection, handle in a new thread so server keeps listening
                threading.Thread(target=self._handle_incoming, args=(conn, addr), daemon=True).start()
        except Exception as e:
            print_err("Server failed:", e)
            traceback.print_exc()
        finally:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass

    def _handle_incoming(self, conn, addr):
        if callable(self.on_connection):
            self.on_connection(conn, addr)

    def stop(self):
        self._stop_event.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    def _local_addrs(self):
        # try to find a usable local IP for display (best-effort)
        try:
            hn = socket.gethostname()
            local = socket.gethostbyname(hn)
            return local
        except Exception:
            return '0.0.0.0'

# --------------------
# Chat session handling
# --------------------
class ChatSession:
    """
    Encapsulates a live chat over a connected socket.
    Handles two threads:
  - recv loop (prints peer messages)
  - send loop (reads input from stdin and sends)
    """
    def __init__(self, conn: socket.socket, peer_addr, username='You', peer_name=None, encryptor=None):
        self.conn = conn
        self.peer_addr = peer_addr
        self.username = username
        self.peer_name = peer_name or f"{peer_addr[0]}:{peer_addr[1]}"
        self.encryptor = encryptor  # None or Fernet instance
        self._recv_thread = None
        self._send_thread = None
        self._stop_event = threading.Event()
        self._incoming_q = queue.Queue()

    def start(self):
        # Start receiver and sender threads. Sender runs in main thread read loop if desired.
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()
        # We'll run input loop in the current thread to allow ctrl-c to break naturally
        try:
            self._input_loop()
        finally:
            self.stop()

    def _recv_loop(self):
        try:
            while not self._stop_event.is_set():
                try:
                    data = self.conn.recv(RECV_BUF)
                except ConnectionResetError:
                    print_info("\n[DISCONNECTED] Peer reset connection.")
                    break
                except OSError:
                    break
                if not data:
                    print_info("\n[DISCONNECTED] Peer closed connection.")
                    break
                # decrypt if needed
                if self.encryptor:
                    try:
                        data = self.encryptor.decrypt(data)
                    except Exception:
                        print_err("\n[ERROR] Failed to decrypt message.")
                        continue
                try:
                    text = data.decode(ENCODING, errors='replace')
                except Exception:
                    text = "<binary data>"
                # print nicely with timestamp
                print(f"\n[{now_stamp()}] {self.peer_name}: {text}")
        finally:
            self._stop_event.set()

    def _input_loop(self):
        try:
            while not self._stop_event.is_set():
                try:
                    msg = input()
                except EOFError:
                    # e.g., user pressed Ctrl-D in some shells
                    break
                except KeyboardInterrupt:
                    print_info("\nInterrupted — closing chat.")
                    break
                msg = msg.rstrip('\n')
                if msg == '':
                    continue
                if msg.lower() in ('/quit', '/exit'):
                    print_info("Exiting chat...")
                    break
                payload = msg.encode(ENCODING)
                if self.encryptor:
                    payload = self.encryptor.encrypt(payload)
                try:
                    self.conn.sendall(payload)
                except Exception:
                    print_err("Failed to send message; connection may be closed.")
                    break
        finally:
            self._stop_event.set()

    def stop(self):
        self._stop_event.set()
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass

# --------------------
# Application glue
# --------------------
def ask_allow(addr):
    """Blockingly ask the local user whether to allow incoming connection from addr."""
    prompt = f"Incoming connection from {addr[0]}:{addr[1]}. Allow? (y/n): "
    while True:
        try:
            ans = input(prompt).strip().lower()
        except KeyboardInterrupt:
            print_info("\nDenying by interrupt.")
            return False
        if ans in ('y', 'yes'):
            return True
        if ans in ('n', 'no'):
            return False
        print("Answer y or n.")

def start_client_connect(target_host, target_port, username, encryptor=None):
    """Attempt to connect to target_host:target_port; returns ChatSession on success."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(CONN_TIMEOUT)
    try:
        print_info(f"Connecting to {target_host}:{target_port} ...")
        s.connect((target_host, target_port))
    except Exception as e:
        print_err(f"Failed to connect: {e}")
        s.close()
        return None
    s.settimeout(None)  # switch to blocking for chat
    # send a simple hello containing our username so the acceptor can display it if desired
    try:
        hello = f"__HELLO__:{username}".encode(ENCODING)
        if encryptor:
            hello = encryptor.encrypt(hello)
        s.sendall(hello)
    except Exception:
        pass
    return ChatSession(s, s.getpeername(), username=username, peer_name=None, encryptor=encryptor)

def on_incoming_connection(conn, addr, username, encryptor):
    """
    Called by server thread when an incoming connection is accepted.
    It performs an allow/deny prompt, receives any initial hello, and if allowed,
    starts a ChatSession.
    """
    # best-effort receive a small hello (non-blocking short timeout)
    try:
        conn.settimeout(2.0)
        raw = conn.recv(4096)
    except Exception:
        raw = b''
    finally:
        conn.settimeout(None)

    peer_name = f"{addr[0]}:{addr[1]}"
    # attempt to decode hello
    hello_name = None
    if raw:
        # if encryption enabled try both decrypt and raw decode — if decrypt fails we'll try plain
        if encryptor:
            try:
                dec = encryptor.decrypt(raw)
                text = dec.decode(ENCODING, errors='replace')
                if text.startswith("__HELLO__:"):
                    hello_name = text.split(":",1)[1]
            except Exception:
                # maybe peer didn't encrypt hello
                try:
                    text = raw.decode(ENCODING, errors='replace')
                    if text.startswith("__HELLO__:"):
                        hello_name = text.split(":",1)[1]
                except Exception:
                    hello_name = None
        else:
            try:
                text = raw.decode(ENCODING, errors='replace')
                if text.startswith("__HELLO__:"):
                    hello_name = text.split(":",1)[1]
            except Exception:
                hello_name = None

    display_from = hello_name or peer_name
    allow = ask_allow(addr)
    if not allow:
        try:
            conn.close()
        except Exception:
            pass
        print_info(f"Connection from {display_from} denied.")
        return

    print_info(f"Accepted connection from {display_from}. Starting chat...")
    # If we consumed the hello, the peer is still waiting for our response; we can continue using conn
    # Start chat session; pass peer_name for nicer display
    session = ChatSession(conn, addr, username=username, peer_name=display_from, encryptor=encryptor)
    session.start()
    print_info("Session ended.")

# --------------------
# Encryption helpers
# --------------------
def make_encryptor_from_key(key_bytes: bytes):
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography not available; install with 'pip install cryptography'")
    return Fernet(key_bytes)

def create_new_key():
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography not available; install with 'pip install cryptography'")
    return Fernet.generate_key()

# --------------------
# CLI and main loop
# --------------------
def main():
    parser = argparse.ArgumentParser(description="Peer-to-peer LAN CLI chat (allow/deny incoming).")
    parser.add_argument('--port', '-p', type=int, default=DEFAULT_PORT, help='listening port')
    parser.add_argument('--host-only', action='store_true', help='just start listening server and do not connect out')
    parser.add_argument('--no-server', action='store_true', help='do not start the listening server (client-only)')
    parser.add_argument('--encrypt', action='store_true', help='enable optional Fernet symmetric encryption (both sides must use the same key)')
    parser.add_argument('--key', type=str, default=None, help='base64 urlsafe key for Fernet if using --encrypt (generated if omitted)')
    parser.add_argument('--username', type=str, default=None, help='your display name (defaults to system hostname)')
    args = parser.parse_args()

    username = args.username or socket.gethostname()
    encryptor = None
    if args.encrypt:
        if not CRYPTO_AVAILABLE:
            print_err("cryptography package not found. Install with: pip install cryptography")
            return
        if args.key:
            key = args.key.encode()
            try:
                encryptor = make_encryptor_from_key(key)
            except Exception as e:
                print_err("Provided key invalid:", e)
                return
            print_info("Encryption enabled with provided key.")
        else:
            key = create_new_key()
            encryptor = make_encryptor_from_key(key)
            print_info("Encryption enabled. Share this key with your peer to chat:")
            print(key.decode())

    # Start server unless explicitly disabled
    server = None
    if not args.no_server:
        server = PeerServer(host='', port=args.port,
                            on_connection=lambda conn, addr: on_incoming_connection(conn, addr, username, encryptor))
        server.start()
    else:
        print_info("Server listener disabled (client-only mode).")

    # Interactive main loop: let user issue connect commands or exit
    try:
        while True:
            try:
                cmd = input("\n[menu] (c)onnect  (i)fconfig  (q)uit > ").strip().lower()
            except KeyboardInterrupt:
                print_info("\nInterrupted.")
                break
            if cmd in ('q', 'quit', 'exit'):
                break
            if cmd in ('i', 'ifconfig', 'info'):
                # display useful local addresses
                print_info("Local hostname:", socket.gethostname())
                try:
                    print_info("Local IP (gethostbyname):", socket.gethostbyname(socket.gethostname()))
                except Exception:
                    pass
                # also show best route IP (connect to an external site sock trick)
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.connect(("8.8.8.8", 80))
                        print_info("Local IP (route):", s.getsockname()[0])
                except Exception:
                    pass
                continue
            if cmd in ('c', 'connect'):
                target = input("Enter target hostname or IP: ").strip()
                if not target:
                    print("No target provided.")
                    continue
                try:
                    target_port_raw = input(f"Enter port [{args.port}]: ").strip()
                    target_port = int(target_port_raw) if target_port_raw else args.port
                except ValueError:
                    print("Invalid port.")
                    continue
                sess = start_client_connect(target, target_port, username=username, encryptor=encryptor)
                if sess:
                    print_info("Connected. Type messages and press enter. Type /quit to exit session.")
                    sess.start()  # this will block until session ends
                else:
                    print_err("Unable to establish session.")
                continue
            print("Unknown command. Type 'c' to connect, 'i' for info, 'q' to quit.")
    finally:
        print_info("Shutting down...")
        if server:
            server.stop()
        time.sleep(0.2)
        print_info("Goodbye.")

if __name__ == '__main__':
    main()
