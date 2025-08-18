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
def generate_signature_keys():
    """
    Generates RSA key pair for signing/verification.
    Returns:
        (public_key, private_key)
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key


# ----------------------------
# Sign a Message
# ----------------------------
def sign_message(private_key, message):
    """
    Creates a digital signature for a message using RSA private key.
    
    Args:
        private_key (bytes): RSA private key
        message (str): message to sign
    
    Returns:
        str: base64 encoded digital signature
    """
    rsa_key = RSA.import_key(private_key)
    hashed = SHA256.new(message.encode("utf-8"))
    signature = pkcs1_15.new(rsa_key).sign(hashed)
    return base64.b64encode(signature).decode("utf-8")


# ----------------------------
# Verify a Message Signature
# ----------------------------
def verify_signature(public_key, message, signature):
    """
    Verifies a digital signature using RSA public key.
    
    Args:
        public_key (bytes): RSA public key
        message (str): original message
        signature (str): base64 encoded digital signature
    
    Returns:
        bool: True if valid, False otherwise
    """
    rsa_key = RSA.import_key(public_key)
    hashed = SHA256.new(message.encode("utf-8"))
    try:
        pkcs1_15.new(rsa_key).verify(hashed, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False


# ----------------------------
# Test (Standalone Run)
# ----------------------------
if __name__ == "__main__":
    # Step 1: Generate signing keys
    public_key, private_key = generate_signature_keys()
    print("[INFO] Digital Signature Keys Generated.")

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
