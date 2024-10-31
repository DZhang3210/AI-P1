from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def aes_ofb_encrypt(plaintext: bytes, key: bytes, iv: bytes = None) -> tuple[bytes, bytes]:
    if not iv:
        iv = os.urandom(16)
    
    # Create cipher object
    cipher = Cipher(
        algorithms.AES(key),
        modes.OFB(iv),
        backend=default_backend()
    )
    
    # Create encryptor
    encryptor = cipher.encryptor()
    
    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return ciphertext, iv

def aes_ofb_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    
    # Create cipher object
    cipher = Cipher(
        algorithms.AES(key),
        modes.OFB(iv),
        backend=default_backend()
    )
    
    # Create decryptor
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext

# Example usage:
if __name__ == "__main__":
    # Example key (32 bytes for AES-256)
    key = os.urandom(32)
    
    # Message to encrypt
    message = input("Enter the message to encrypt: ")
    message_bytes = message.encode('utf-8')
    print(f"Message: {message}")
    
    # Encrypt
    ciphertext, iv = aes_ofb_encrypt(message_bytes, key)
    print(f"Encrypted: {ciphertext.hex()}")
    
    # Decrypt
    decrypted = aes_ofb_decrypt(ciphertext, key, iv)
    print(f"Decrypted: {decrypted.decode()}")
