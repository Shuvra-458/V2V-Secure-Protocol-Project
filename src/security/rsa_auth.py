"""
RSA Authentication & Key Exchange Module
----------------------------------------
Provides functions to generate RSA key pairs,
encrypt AES keys with a public key, and decrypt them
with the corresponding private key.
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# ----------------------------
# Generate RSA Key Pair
# ----------------------------
def generate_rsa_keys(key_size=3072):
    """
    Generates RSA public and private keys.
    Args:
        key_size (int): RSA key size in bits (2048 or 3072 recommended)
    Returns:
        (public_key_bytes, private_key_bytes)
    """
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

# ----------------------------
# Encrypt AES Key with RSA Public Key
# ----------------------------
def encrypt_aes_key(public_key, aes_key, label=b""):
    """
    Encrypts an AES key using the recipient's RSA public key.

    Args:
        public_key (bytes): RSA public key
        aes_key (bytes): AES session key
        label (bytes, optional): Optional label for OAEP

    Returns:
        str: base64 encoded encrypted AES key
    """
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key, label=label)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return base64.b64encode(encrypted_key).decode("utf-8")

# ----------------------------
# Decrypt AES Key with RSA Private Key
# ----------------------------
def decrypt_aes_key(private_key, encrypted_aes_key, label=b""):
    """
    Decrypts an AES key using the recipient's RSA private key.

    Args:
        private_key (bytes): RSA private key
        encrypted_aes_key (str): base64 encoded encrypted AES key
        label (bytes, optional): Optional label for OAEP

    Returns:
        bytes: original AES session key
    """
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key, label=label)
    decrypted_key = cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))
    return decrypted_key

# ----------------------------
# Test (Standalone Run)
# ----------------------------
if __name__ == "__main__":
    from aes_encryption import generate_aes_key

    # Step 1: Generate RSA keys for Vehicle 1 (receiver)
    public_key, private_key = generate_rsa_keys(key_size=3072)  # Use 3072 bits for realism
    print("[INFO] RSA Keys Generated (3072 bits).")

    # Step 2: Vehicle 2 generates AES session key
    aes_key = generate_aes_key(32)  # Use 256-bit AES key for realism
    print("[INFO] AES Key Generated:", base64.b64encode(aes_key).decode())

    # Step 3: Vehicle 2 encrypts AES key using Vehicle 1's public key
    encrypted_aes = encrypt_aes_key(public_key, aes_key)
    print("[INFO] Encrypted AES Key:", encrypted_aes)

    # Step 4: Vehicle 1 decrypts AES key using its private key
    decrypted_aes = decrypt_aes_key(private_key, encrypted_aes)
    print("[INFO] Decrypted AES Key:", base64.b64encode(decrypted_aes).decode())

    # Verify
    print("[RESULT] Key Match:", decrypted_aes == aes_key)