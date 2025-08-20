import unittest
from src.security.aes_encryption import generate_aes_key, encrypt_message, decrypt_message
from src.security.rsa_auth import generate_rsa_keys, encrypt_aes_key, decrypt_aes_key
from src.security.digital_signature import generate_signature_keys, sign_message, verify_signature

class TestSecurityModules(unittest.TestCase):

    def test_aes_encryption(self):
        key = generate_aes_key()
        print("\nEnter a message to test AES encryption (default: 'Accident ahead at Highway-34'):")
        message = input("> ").strip() or "Accident ahead at Highway-34"
        encrypted = encrypt_message(key, message)
        decrypted = decrypt_message(key, encrypted)
        self.assertEqual(message, decrypted, "AES Decryption failed!")
        print("✅ AES encryption/decryption successful")

    def test_rsa_key_exchange(self):
        public_key, private_key = generate_rsa_keys()
        aes_key = generate_aes_key()
        encrypted_aes = encrypt_aes_key(public_key, aes_key)
        decrypted_aes = decrypt_aes_key(private_key, encrypted_aes)
        self.assertEqual(aes_key, decrypted_aes, "RSA Key Exchange failed!")
        print("✅ RSA key exchange successful")

    def test_digital_signature(self):
        public_key, private_key = generate_signature_keys()
        print("\nEnter a message to sign (default: 'Emergency brake applied'):")
        message = input("> ").strip() or "Emergency brake applied"
        signature = sign_message(private_key, message)

        self.assertTrue(verify_signature(public_key, message, signature),
                        "Signature verification failed for valid message!")
        print("Enter a tampered message to test signature verification (default: 'Fake Alert'):")
        tampered = input("> ").strip() or "Fake Alert"
        self.assertFalse(verify_signature(public_key, tampered, signature),
                         "Tampered message incorrectly verified as valid!")
        print("✅ Digital signature verified correctly")

if __name__ == "__main__":
    unittest.main()