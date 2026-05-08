from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate RSA key pairs for both the sender and the receiver. These keys will be stored as .pem files.


def generate_rsa_key_pair(private_key_file, public_key_file):
    # Generate private and public keys
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save private key to file
    with open(private_key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save public key to file
    with open(public_key_file, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


generate_rsa_key_pair("./keys/sender_private_key.pem", "./keys/sender_public_key.pem")
generate_rsa_key_pair(
    "./keys/receiver_private_key.pem", "./keys/receiver_public_key.pem"
)
print("RSA key pairs generated for the sender and the receiver.")
