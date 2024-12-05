from Crypto.Hash import HMAC, MD5


def calculate_hmac(plaintext, key):
    """Calculate the HMAC of the plaintext using the given key."""
    hmac = HMAC.new(key, digestmod=MD5)
    hmac.update(plaintext.encode())
    return hmac.hexdigest()


def verify_hmac(plaintext, key, mac_file):
    """Verify HMAC by comparing calculated HMAC with the MAC in the file."""
    with open(mac_file, "r") as f:
        mac_from_file = f.read().strip().lower()
    calculated_hmac = calculate_hmac(plaintext, key)
    print(f"Calculated HMAC: {calculated_hmac}")
    print(f"HMAC from file: {mac_from_file}")
    return calculated_hmac == mac_from_file


if __name__ == "__main__":
    # Load plaintext
    with open("decrypted_plaintext.txt", "r") as file:
        plaintext = file.read()

    # Use the correct keys
    key1 = bytes.fromhex("2a0245f542c0d0c7b6fce2b5dc511a62")
    key2 = bytes.fromhex("68d8aaef41c9c43ec483144cb8349800")

    # Verify HMACs
    mac1_valid = verify_hmac(plaintext, key1, "../ciphertext_and_keys/ciphertext.mac1.txt")
    mac2_valid = verify_hmac(plaintext, key2, "../ciphertext_and_keys/ciphertext.mac2.txt")

    print("***********************************************")
    print(f"MAC 1 Valid: {mac1_valid}")
    print(f"MAC 2 Valid: {mac2_valid}")
    print("***********************************************")
