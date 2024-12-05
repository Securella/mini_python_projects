import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import unpad
from Crypto.Hash import HMAC, MD5
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA1

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class DecryptionProcessor:
    """Handles decryption of ciphertext and keys."""
    def __init__(self, private_key_path, ciphertext_file):
        self.private_key_path = private_key_path
        self.ciphertext_file = ciphertext_file

    def decrypt_rsa(self, encrypted_data):
        """Decrypt RSA-encrypted data using PKCS1 v1.5 padding."""
        try:
            with open(self.private_key_path, "rb") as key_file:
                private_key = RSA.import_key(key_file.read())
            cipher_rsa = PKCS1_v1_5.new(private_key)
            return cipher_rsa.decrypt(encrypted_data, None)
        except Exception as e:
            logging.error(f"RSA decryption failed: {e}")
            raise

    def decrypt_aes(self, ciphertext, key, iv):
        """Decrypt AES-encrypted data using the given key and IV."""
        try:
            aes_cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)
            return plaintext.decode("utf-8")
        except Exception as e:
            logging.error(f"AES decryption failed: {e}")
            raise

    def process(self):
        """Process the ciphertext file to extract and decrypt data."""
        logging.info("Starting decryption process.")
        with open(self.ciphertext_file, "rb") as f:
            data = f.read()

        encrypted_key1, encrypted_iv, encrypted_key2, encrypted_ciphertext = (
            data[:128], data[128:256], data[256:384], data[384:]
        )

        key1 = self.decrypt_rsa(encrypted_key1)
        iv = self.decrypt_rsa(encrypted_iv)
        key2 = self.decrypt_rsa(encrypted_key2)
        plaintext = self.decrypt_aes(encrypted_ciphertext, key1, iv)

        return key1, iv, key2, plaintext


class Verifier:
    """Handles HMAC and signature verification."""
    @staticmethod
    def calculate_hmac(plaintext, key):
        """Calculate the HMAC of the plaintext using the given key."""
        hmac = HMAC.new(key, digestmod=MD5)
        hmac.update(plaintext)
        return hmac.hexdigest()

    @staticmethod
    def verify_hmac(plaintext, key, mac_file):
        """Verify HMAC by comparing calculated and stored values."""
        with open(mac_file, "r") as f:
            mac_from_file = f.read().strip().lower()
        calculated_hmac = Verifier.calculate_hmac(plaintext, key)
        is_valid = calculated_hmac == mac_from_file
        logging.info(f"HMAC Valid: {is_valid} (Calculated: {calculated_hmac}, From File: {mac_from_file})")
        return is_valid

    @staticmethod
    def verify_signature(plaintext, signature_path, cert_path):
        """Verify the digital signature using the public certificate."""
        with open(cert_path, "rb") as cert_file:
            cert = load_pem_x509_certificate(cert_file.read())
        public_key = cert.public_key()

        with open(signature_path, "rb") as sig_file:
            signature = sig_file.read()

        try:
            public_key.verify(
                signature,
                plaintext,
                padding.PKCS1v15(),
                SHA1()
            )
            return True
        except Exception:
            return False


def main():
    # Configuration
    config = {
        "ciphertext_file": "../ciphertext_and_keys/ciphertext.enc",
        "private_key_path": "../ciphertext_and_keys/lab1Store.pem",
        "mac1_file": "../ciphertext_and_keys/ciphertext.mac1.txt",
        "mac2_file": "../ciphertext_and_keys/ciphertext.mac2.txt",
        "sig1_file": "../ciphertext_and_keys/ciphertext.enc.sig1",
        "sig2_file": "../ciphertext_and_keys/ciphertext.enc.sig2",
        "cert_file": "../ciphertext_and_keys/lab1Sign.cert"
    }

    try:
        # Decrypt ciphertext
        decryption_processor = DecryptionProcessor(config["private_key_path"], config["ciphertext_file"])
        key1, iv, key2, plaintext = decryption_processor.process()

        # Display decrypted data
        print("***********************************************")
        print("Decryption Results")
        print("***********************************************")
        print(f"Key 1: {key1.hex()}")
        print(f"IV: {iv.hex()}")
        print(f"Key 2: {key2.hex()}")
        print(f"Decrypted Plaintext:\n{plaintext}")
        print("***********************************************\n")

        # Verify MACs
        plaintext_bytes = plaintext.encode("utf-8")
        mac1_valid = Verifier.verify_hmac(plaintext_bytes, key1, config["mac1_file"])
        mac2_valid = Verifier.verify_hmac(plaintext_bytes, key2, config["mac2_file"])

        print("***********************************************")
        print("MAC Verification Results")
        print("***********************************************")
        print(f"MAC 1 Valid: {mac1_valid}")
        print(f"MAC 2 Valid: {mac2_valid}")
        print("***********************************************\n")

        # Verify Signatures
        sig1_valid = Verifier.verify_signature(plaintext_bytes, config["sig1_file"], config["cert_file"])
        sig2_valid = Verifier.verify_signature(plaintext_bytes, config["sig2_file"], config["cert_file"])

        print("***********************************************")
        print("Signature Verification Results")
        print("***********************************************")
        print(f"Signature 1 Valid: {sig1_valid}")
        print(f"Signature 2 Valid: {sig2_valid}")
        print("***********************************************")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
