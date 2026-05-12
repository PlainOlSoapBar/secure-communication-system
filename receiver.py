import json
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Receive and decrypt the encrypted message.txt file. Display the recovered message.


def load_private_key(filename):
    # Load the RSA private key PEM file.

    with open(filename, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    return private_key


def verify_hmac(hmac_key, data, received_mac):
    # Verify HMAC. If the MAC is invalid, an InvalidSignature exception is raised.

    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(data)
    h.verify(received_mac)


def aes_decrypt(ciphertext, aes_key, iv):
    # Decrypt AES-CBC ciphertext and remove padding.
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))

    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


def main():
    # Receiver uses its private key to decrypt the data.
    receiver_private_key = load_private_key("./keys/receiver_private_key.pem")

    # Read transmitted data.
    with open("Transmitted_Data.json", "r") as f:
        transmitted_data = json.load(f)

    encrypted_session_keys = base64.b64decode(
        transmitted_data["encrypted_session_keys"]
    )
    iv = base64.b64decode(transmitted_data["iv"])
    ciphertext = base64.b64decode(transmitted_data["ciphertext"])
    received_mac = base64.b64decode(transmitted_data["mac"])

    # Decrypt AES key and HMAC key using the receiver's RSA private key.
    session_keys = receiver_private_key.decrypt(
        encrypted_session_keys,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    aes_key = session_keys[:32]
    hmac_key = session_keys[32:]

    # Verify MAC before decrypting.
    mac_data = encrypted_session_keys + iv + ciphertext

    try:
        verify_hmac(hmac_key, mac_data, received_mac)
        print("MAC verification successful. Data is authentic and unchanged.")
    except InvalidSignature:
        print("MAC verification failed. Data may have been modified.")
        return

    # Decrypt message.
    plaintext = aes_decrypt(ciphertext, aes_key, iv)

    print("Message decrypted successfully.")
    print("Recovered message:", plaintext.decode("utf-8"))

if __name__ == "__main__":
    main()
