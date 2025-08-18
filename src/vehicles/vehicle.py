"""
Vehicle Module
--------------
Defines a vehicle that can send/receive secure messages
using AES, RSA, and Digital Signatures.
"""

import base64
from src.security.aes_encryption import generate_aes_key, encrypt_message, decrypt_message
from src.security.rsa_auth import generate_rsa_keys, encrypt_aes_key, decrypt_aes_key
from src.security.digital_signature import generate_signature_keys, sign_message, verify_signature
from src.network.message_format import create_message, parse_message


class Vehicle:
    def __init__(self, vehicle_id):
        self.id = vehicle_id

        # RSA for key exchange
        self.public_key, self.private_key = generate_rsa_keys()

        # AES session key (shared later)
        self.aes_key = None

        # Digital signature keys
        self.sig_public, self.sig_private = generate_signature_keys()

    def generate_aes_key(self):
        """Generate new AES session key"""
        self.aes_key = generate_aes_key()
        return self.aes_key

    def encrypt_session_key(self, receiver_public):
        """Encrypt AES key with receiver's public RSA key"""
        return encrypt_aes_key(receiver_public, self.aes_key)

    def decrypt_session_key(self, encrypted_key):
        """Decrypt AES key with own private RSA key"""
        self.aes_key = decrypt_aes_key(self.private_key, encrypted_key)
        return self.aes_key

    def send_secure_message(self, event, speed, location):
        """Create a signed + encrypted secure message"""
        plain_msg = create_message(self.id, event, speed, location)

        # sign
        signature = sign_message(self.sig_private, plain_msg)

        # combine msg + signature
        combined = plain_msg + "||" + signature

        # encrypt with AES
        encrypted = encrypt_message(self.aes_key, combined)
        return encrypted.encode('utf-8')

    def receive_secure_message(self, encrypted, sender_sig_pub):
        """Decrypt + verify secure message"""
        decrypted = decrypt_message(self.aes_key, encrypted.decode('utf-8'))

        # split message + signature
        try:
            msg, signature = decrypted.split("||")
        except ValueError:
            return None, False

        # verify signature
        valid = verify_signature(sender_sig_pub, msg, signature)
        return parse_message(msg), valid
