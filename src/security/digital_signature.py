"""
Digital Signature Module
------------------------
Provides functions to sign and verify messages
using RSA private/public keys + SHA-256 hashing.
"""

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

# ----------------------------
# Generate RSA Keys (for signing)
# ----------------------------
def generate_signature_keys(key_size=2048):
    """
    Generates RSA key pair for signing/verification.
    Args:
        key_size (int): RSA key size in bits (2048 or 3072 recommended)
    Returns:
        (public_key, private_key)
    """
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

# ----------------------------
# Sign a Message
# ----------------------------
def sign_message(private_key, message, encoding="utf-8"):
    """
    Creates a digital signature for a message using RSA private key.

    Args:
        private_key (bytes): RSA private key
        message (str): message to sign
        encoding (str): encoding for message (default: utf-8)

    Returns:
        str: base64 encoded digital signature
    """
    rsa_key = RSA.import_key(private_key)
    hashed = SHA256.new(message.encode(encoding))
    signature = pkcs1_15.new(rsa_key).sign(hashed)
    return base64.b64encode(signature).decode("utf-8")

# ----------------------------
# Verify a Message Signature
# ----------------------------
def verify_signature(public_key, message, signature, encoding="utf-8"):
    """
    Verifies a digital signature using RSA public key.

    Args:
        public_key (bytes): RSA public key
        message (str): original message
        signature (str): base64 encoded digital signature
        encoding (str): encoding for message (default: utf-8)

    Returns:
        bool: True if valid, False otherwise
    """
    rsa_key = RSA.import_key(public_key)
    hashed = SHA256.new(message.encode(encoding))
    try:
        pkcs1_15.new(rsa_key).verify(hashed, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False

# ----------------------------
# Test (Standalone Run)
# ----------------------------
if __name__ == "__main__":
    # Step 1: Generate signing keys (3072 bits for higher realism)
    public_key, private_key = generate_signature_keys(key_size=3072)
    print("[INFO] Digital Signature Keys Generated (3072 bits).")

    # Step 2: Sign a message
    message = "Accident ahead at Highway-34"
    signature = sign_message(private_key, message)
    print("[INFO] Message:", message)
    print("[INFO] Signature:", signature)

    # Step 3: Verify signature
    is_valid = verify_signature(public_key, message, signature)
    print("[RESULT] Signature Valid:", is_valid)

    # Step 4: Test with tampered message
    is_valid_tampered = verify_signature(public_key, "Fake Accident Alert", signature)
    print("[RESULT] Tampered Message Valid:", is_valid_tampered)