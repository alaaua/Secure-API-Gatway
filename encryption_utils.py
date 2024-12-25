from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os

# Key and Initialization Vector (IV)
AES_KEY = os.urandom(32)  # 256-bit key
IV = os.urandom(16)       # 128-bit IV

# Encrypt Data
def encrypt_data(data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV), backend=backend)

    # Pad the data
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    # Encrypt
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(IV + encrypted_data).decode()

# Decrypt Data
def decrypt_data(encrypted_data):
    backend = default_backend()
    encrypted_data_bytes = base64.b64decode(encrypted_data)

    iv = encrypted_data_bytes[:16]
    cipher_data = encrypted_data_bytes[16:]

    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(cipher_data) + decryptor.finalize()

    # Unpad the data
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return data.decode()
