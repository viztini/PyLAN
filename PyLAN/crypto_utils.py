from cryptography.fernet import Fernet

# Generate a new encryption key
def generate_key():
    return Fernet.generate_key()

# Create Fernet cipher object from a key
def get_cipher(key):
    return Fernet(key)

# Encrypt message bytes using given key
def encrypt_message(message, key):
    cipher = get_cipher(key)
    return cipher.encrypt(message.encode())

# Decrypt message bytes using given key
def decrypt_message(encrypted_message, key):
    cipher = get_cipher(key)
    try:
        return cipher.decrypt(encrypted_message).decode()
    except Exception:
        return "[DECRYPTION FAILED]"
