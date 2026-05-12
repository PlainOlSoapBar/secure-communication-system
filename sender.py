import os
import json
import base64

from cryptography.hazmat.primitives import hashes, hmac, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Uses RSA keys to encrypt the message.txt file and send it to the receiver.


def load_public_key(filename):
    # Load the RSA public key PEM file.
    with open(filename, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return public_key


def aes_encrypt(plaintext, aes_key, iv):
    # Encrypt plaintext using AES-CBC with padding.
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext


def compute_hmac(hmac_key, data):
    # Compute HMAC over the given data.
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def main():
    # Receiver uses its private key to decrypt the data.
    receiver_public_key = load_public_key("./keys/receiver_public_key.pem")

    # Read message from text file.
    with open("message.txt", "rb") as f:
        plaintext = f.read()

    # Generate AES key and HMAC key.
    aes_key = os.urandom(32)
    hmac_key = os.urandom(32)

    # Generate IV for AES-CBC.
    iv = os.urandom(16)

    # Encrypt the message using AES.
    ciphertext = aes_encrypt(plaintext, aes_key, iv)

    # Combine AES key and HMAC key into one session key package.
    session_keys = aes_key + hmac_key

    # Encrypt session keys using the receiver's RSA public key.
    encrypted_session_keys = receiver_public_key.encrypt(
        session_keys,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Compute HMAC over the transmitted encrypted data.
    mac_data = encrypted_session_keys + iv + ciphertext
    mac = compute_hmac(hmac_key, mac_data)

    # Save transmitted data as base64-encoded JSON.
    transmitted_data = {
        "encrypted_session_keys": base64.b64encode(encrypted_session_keys).decode(
            "utf-8"
        ),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "mac": base64.b64encode(mac).decode("utf-8"),
    }

    with open("Transmitted_Data.json", "w") as f:
        json.dump(transmitted_data, f, indent=4)

    print("Message encrypted and written to Transmitted_Data.json.")

if __name__ == "__main__":
    main()
