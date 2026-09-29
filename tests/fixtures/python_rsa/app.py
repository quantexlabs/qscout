"""Sample Python app with RSA encryption for CRYPTO-002."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PRIVATE_KEY = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MZQlKNjvdhU6LpkN
zV1bEe5rYJQYzQJQYzQJQYzQJQYzQJQYzQJQYzQJQYzQJQYzQJQYzQJQYzQJQYzQ
-----END RSA PRIVATE KEY-----"""


def encrypt_data(plaintext: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def generate_weak_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)
