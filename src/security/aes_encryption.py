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
def generate_aes_key(length=16):
    """
    Generates a random AES key.
    Args:
        length (int): Key length in bytes (16=128bit, 24=192bit, 32=256bit)
    Returns:
        key (bytes): AES secret key
    """
    if length not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes long.")
    return get_random_bytes(length)


# ----------------------------
# Encrypt Message
# ----------------------------
def encrypt_message(key, plaintext, associated_data=None):
    """
    Encrypts a plaintext message using AES (EAX mode).
    Args:
        key (bytes): AES key
        plaintext (str): message to encrypt
        associated_data (bytes, optional): additional data to authenticate (not encrypted)
    Returns:
        str: base64 encoded encrypted message (nonce + tag + ciphertext)
    """
    if key is None:
        raise ValueError("AES key cannot be None")
    if plaintext is None:
        raise ValueError("Plaintext cannot be None")

    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    cipher = AES.new(key, AES.MODE_EAX)
    if associated_data:
        cipher.update(associated_data)

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    result = cipher.nonce + tag + ciphertext
    return base64.b64encode(result).decode("utf-8")


# ----------------------------
# Decrypt Message
# ----------------------------
def decrypt_message(key, encrypted_text, associated_data=None):
    """
    Decrypts a base64 encoded encrypted message using AES (EAX mode).
    Args:
        key (bytes): AES key
        encrypted_text (str): encrypted message (base64)
        associated_data (bytes, optional): additional data to authenticate
    Returns:
        str: decrypted plaintext
    Raises:
        ValueError: if decryption or authentication fails
    """
    if key is None:
        raise ValueError("AES key cannot be None")
    if encrypted_text is None:
        raise ValueError("Encrypted text cannot be None")

    try:
        raw = base64.b64decode(encrypted_text)
    except Exception:
        raise ValueError("Invalid ciphertext format (Base64 decode failed)")

    if len(raw) < 32:  # 16 nonce + 16 tag + min(1) ciphertext
        raise ValueError("Ciphertext too short to contain AES nonce+tag")

    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    if associated_data:
        cipher.update(associated_data)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        raise ValueError(f"Decryption failed: {str(e)}")

    return plaintext.decode("utf-8")


# ----------------------------
# Test (Standalone Run)
# ----------------------------
if __name__ == "__main__":
    key = generate_aes_key(32)  # Use 256-bit key for realism
    print("[INFO] AES Key Generated:", base64.b64encode(key).decode())

    original_message = "Accident ahead at Highway-34"
    print("[INFO] Original Message:", original_message)

    encrypted = encrypt_message(key, original_message)
    print("[INFO] Encrypted Message:", encrypted)

    decrypted = decrypt_message(key, encrypted)
    print("[INFO] Decrypted Message:", decrypted)
