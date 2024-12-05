# 🌟 Labs Solution: Decrypting and Verifying Messages in Secure Communication

## 📖 Overview
This project implements solutions to the **Decrypt and Recover Plaintext** and **Verify Authenticity and Integrity** labs. It handles:
- Secure decryption of ciphertext and keys.
- Verification of integrity and authenticity using cryptographic methods like **RSA**, **AES**, **HMAC**, and **Digital Signatures**.

---

## ✨ Features

### 🔐 Lab 1: Decrypt and Recover Plaintext
1. **Key Decryption**:
   - Decrypt `Key1`, `IV`, and `Key2` using a private key.
2. **Plaintext Recovery**:
   - Decrypt the main ciphertext using AES with `Key1` and `IV`.

### ✅ Lab 2: Verify Authenticity and Integrity
1. **HMAC Validation**:
   - Calculate and validate HMACs using the decrypted plaintext and keys.
2. **Digital Signature Verification**:
   - Verify signatures using a provided certificate.

### 📝 Outputs
- **Decrypted Data**:
  - Keys (`Key1`, `IV`, `Key2`).
  - Plaintext.
- **Validation Results**:
  - HMAC checks.
  - Signature checks.

---

## 🚀 How to Run

### Prerequisites
Required libraries:
   ```bash
   pip install pycryptodome cryptography
   ```

### 🔍 Open Questions and Answers
***Why is it not a good idea to encrypt the plaintext with the receiver’s public key? Why generate Key1, IV, and encrypt them?***:
Encrypting plaintext directly with a public key is not ideal due to:

- Performance: Public key encryption (e.g., RSA) is slow and unsuitable for large data.
- Size Limitations: RSA can only encrypt small chunks of data (e.g., 2048-bit RSA encrypts ~256 bytes).
- Improved Security: Generating a unique session key (Key1) and IV for each session adds forward secrecy, ensuring that even if a key is compromised, previous sessions remain secure.

***Does a verified MAC authenticate the sender or ensure the origin of the message?***:
No, a verified MAC alone does not authenticate the sender or guarantee the origin. Here’s why:

- Message Integrity: A MAC ensures the message wasn't altered but doesn’t prove who sent it.
- Lack of Pre-Shared Secret: If no pre-shared secret exists between sender and receiver, anyone intercepting the encrypted keys (Key1, Key2) could calculate a valid MAC.
- No Proof of Identity: Unlike digital signatures, MACs do not rely on asymmetric cryptography and cannot confirm the sender’s identity.