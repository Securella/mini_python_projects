import jks
from Crypto.PublicKey import RSA


def extract_private_key(jks_path, store_password, key_alias, key_password):
    # Load the Java KeyStore
    keystore = jks.KeyStore.load(jks_path, store_password)

    # Extract the private key entry
    pk_entry = keystore.private_keys[key_alias]
    if not pk_entry.is_decrypted():
        pk_entry.decrypt(key_password)

    # Convert the key to PEM format
    private_key = RSA.import_key(pk_entry.pkey)
    return private_key


if __name__ == "__main__":
    # Update the path to the correct location
    jks_path = "../ciphertext_and_keys/lab1Store"  # Correctly reference the directory
    store_password = "lab1StorePass"
    key_alias = "lab1enckeys"
    key_password = "lab1KeyPass"

    private_key = extract_private_key(jks_path, store_password, key_alias, key_password)
    with open("lab1Store.pem", "wb") as key_file:
        key_file.write(private_key.export_key())
    print("Private key saved to lab1Store.pem.")
