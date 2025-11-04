````markdown
# PyLAN Messenger

A lightweight peer-to-peer LAN messaging application written entirely in Python.  
Two users can chat directly over a local network: one acts as a host and the other connects using the host’s machine name or IP.  
No external servers, accounts, or frameworks are required.

---

## Overview

PyLAN Messenger is designed for simple, encrypted, local communication between two Windows or cross-platform machines running Python.  
Each instance functions as both a client and a listener.  
The receiver must explicitly approve a connection request before messages are exchanged.

---

## Features

- Direct peer-to-peer TCP communication  
- Manual connection approval for security  
- AES encryption (via `cryptography.fernet`)  
- Concurrent sending and receiving using threads  
- Works on Windows, macOS, and Linux (Python 3.10+)  
- No internet access required — LAN only

---

## How It Works

1. Each user runs the application.  
2. One user shares their hostname or IP address.  
3. The second user connects to that address.  
4. The host is prompted to approve or deny the request.  
5. Once approved, both users can exchange messages in real time.

Internally, each instance spawns a small TCP server (for incoming messages) and a client socket (for outgoing messages).  
All traffic is encrypted with a shared secret key generated at runtime.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/viztini/PyLAN.git
cd PyLAN-Messenger
````

Install dependencies:

```bash
pip install -r requirements.txt
```

Contents of `requirements.txt`:

```
cryptography
```

---

## Usage

You can start PyLAN Messenger in two modes: **host** or **client**.

### Start as Host

```bash
python server.py
```

The host will see a message like:

```
Listening on 192.168.1.15:5000
```

When another user tries to connect, you will be asked to approve.
Once approved, you can exchange encrypted messages.

### Connect as Client

```bash
python client.py
```

You will be prompted to enter the hostname or IP of the person you want to contact:

```
Enter target hostname or IP: 192.168.1.15
```

After the host approves your request, you can begin chatting.

---

## File Structure

```
PyLAN-Messenger/
├── client.py             # Client logic and message sender
├── server.py             # Host listener and message handler
├── crypto_utils.py       # Encryption and key management
├── requirements.txt      # Dependencies
└── README.md             # Project documentation
```

---

## Technical Details

### Encryption

Messages are encrypted using the Fernet (AES-128 in CBC mode + HMAC) implementation from the `cryptography` library.
Each session generates a new shared key that must match between peers to decrypt messages correctly.

### Networking

The server listens on a configurable port (default 5000).
Messages are exchanged using TCP sockets and processed concurrently via threading.

### Concurrency

Each user runs two threads:

* One for sending input from the console.
* One for listening and displaying incoming messages.

This prevents blocking during active conversations.

---

## Security Considerations

* This project is designed for **trusted LANs**; it does not include advanced key exchange or TLS.
* Messages are encrypted in transit but not stored.
* Connections require **explicit approval** before any data is exchanged.
* Use strong local network passwords if testing in public environments.

---

## Known Limitations

* One-to-one communication only (no group chat yet).
* Both participants must be on the same LAN.
* Encryption key sharing occurs implicitly at connection time — not via a formal key exchange protocol.
* Message history is not saved by default.

---

## Example Session

```
[Host] Listening on 192.168.1.15:5000
[Client] Connecting to 192.168.1.15:5000...
[Host] Incoming connection from 192.168.1.23. Approve? (y/n): y
[Host] Connection approved.
[Client] Connection established.
[You]: hey
[Peer]: hi, connection works perfectly.
```

---

## Future Improvements

* Add Diffie-Hellman key exchange
* Support multiple peers and group chats
* Implement file transfer
* Optional persistent message logging
* GUI version using Tkinter or PyQt

---

## License

This project is released under the MIT License.
See the [LICENSE](LICENSE) file for details.

---

## Author

Developed by **viztini with help from MattDaNerd**.
Created for experimentation, learning, and open collaboration in local networking and Python concurrency.

---

```
```
