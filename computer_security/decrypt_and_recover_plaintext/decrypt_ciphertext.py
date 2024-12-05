from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import unpad


def decrypt_aes(ciphertext, key, iv):
    """Decrypt AES-encrypted data using the given key and IV."""
    aes_cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()


if __name__ == "__main__":
    # Load the private key
    with open("../ciphertext_and_keys/lab1Store.pem", "rb") as key_file:
        private_key_pem = key_file.read()

    # Path to ciphertext file
    ciphertext_path = "../ciphertext_and_keys/ciphertext.enc"

    # Load the private key and prepare decryption
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_v1_5.new(private_key)  # Use PKCS1 v1.5 padding

    # Read the ciphertext
    with open(ciphertext_path, "rb") as f:
        data = f.read()

    # Split into components
    enc_key1, enc_iv, enc_key2, ciphertext = data[:128], data[128:256], data[256:384], data[384:]

    # Decrypt the keys
    key1 = cipher_rsa.decrypt(enc_key1, None)
    iv = cipher_rsa.decrypt(enc_iv, None)
    key2 = cipher_rsa.decrypt(enc_key2, None)

    print(f"Key1: {key1.hex()}")
    print(f"IV: {iv.hex()}")
    print(f"Key2: {key2.hex()}")

    # Decrypt the AES-encrypted ciphertext
    plaintext = decrypt_aes(ciphertext, key1, iv)
    print("Decrypted Plaintext:")
    print(plaintext)

    # Save plaintext to a file for MAC and signature verification
    with open("decrypted_plaintext.txt", "w") as plaintext_file:
        plaintext_file.write(plaintext)
