"""
AES Encryption / Decryption Module
----------------------------------
Provides functions to encrypt and decrypt messages using AES.
Mode used: AES EAX (provides both confidentiality + integrity).
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# ----------------------------
# Generate AES Key
# ----------------------------
def generate_aes_key():
    """
    Generates a random 16-byte AES key.
    Returns:
        key (bytes): AES secret key
    """
    return get_random_bytes(16)  # 128-bit key


# ----------------------------
# Encrypt Message
# ----------------------------
def encrypt_message(key, plaintext):
    """
    Encrypts a plaintext message using AES (EAX mode).
    
    Args:
        key (bytes): AES key
        plaintext (str): message to encrypt
    
    Returns:
        str: base64 encoded encrypted message (nonce + tag + ciphertext)
    """
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode("utf-8")


# ----------------------------
# Decrypt Message
# ----------------------------
def decrypt_message(key, encrypted_text):
    """
    Decrypts a base64 encoded encrypted message using AES (EAX mode).
    
    Args:
        key (bytes): AES key
        encrypted_text (str): encrypted message (base64)
    
    Returns:
        str: decrypted plaintext
    """
    raw = base64.b64decode(encrypted_text)
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")


# ----------------------------
# Test (Standalone Run)
# ----------------------------
if __name__ == "__main__":
    key = generate_aes_key()
    print("[INFO] AES Key Generated:", key)

    original_message = "Accident ahead at Highway-34"
    print("[INFO] Original Message:", original_message)

    encrypted = encrypt_message(key, original_message)
    print("[INFO] Encrypted Message:", encrypted)

    decrypted = decrypt_message(key, encrypted)
    print("[INFO] Decrypted Message:", decrypted)
