from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA1


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
            plaintext.encode("utf-8"),
            padding.PKCS1v15(),
            SHA1()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False


if __name__ == "__main__":
    # Load plaintext
    with open("decrypted_plaintext.txt", "r") as file:
        plaintext = file.read()

    # Verify signatures
    sig1_valid = verify_signature(plaintext, "../ciphertext_and_keys/ciphertext.enc.sig1", "../ciphertext_and_keys/lab1Sign.cert")
    sig2_valid = verify_signature(plaintext, "../ciphertext_and_keys/ciphertext.enc.sig2", "../ciphertext_and_keys/lab1Sign.cert")

    print("***********************************************")
    print(f"Signature 1 Valid: {sig1_valid}")
    print(f"Signature 2 Valid: {sig2_valid}")
    print("***********************************************")
