from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def decrypt_keys(private_key_pem, ciphertext_path):
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)

    with open(ciphertext_path, 'rb') as f:
        data = f.read()

    enc_key1, enc_iv, enc_key2, ciphertext = data[:128], data[128:256], data[256:384], data[384:]

    print(f"Encrypted Key1: {enc_key1.hex()}")
    print(f"Encrypted IV: {enc_iv.hex()}")
    print(f"Encrypted Key2: {enc_key2.hex()}")
    print(f"Ciphertext Length: {len(ciphertext)} bytes")

    try:
        key1 = cipher_rsa.decrypt(enc_key1)
        print(f"Decrypted Key1: {key1.hex()}")
    except ValueError as e:
        print(f"Error decrypting Key1: {e}")
        raise

    try:
        iv = cipher_rsa.decrypt(enc_iv)
        print(f"Decrypted IV: {iv.hex()}")
    except ValueError as e:
        print(f"Error decrypting IV: {e}")
        raise

    try:
        key2 = cipher_rsa.decrypt(enc_key2)
        print(f"Decrypted Key2: {key2.hex()}")
    except ValueError as e:
        print(f"Error decrypting Key2: {e}")
        raise

    return key1, iv, key2, ciphertext
