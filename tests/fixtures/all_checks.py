"""Synthetic source triggering multiple check kinds for tests."""

import hashlib

# CRYPTO-006: hardcoded key
SECRET = "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"

# CRYPTO-007: weak hash
digest = hashlib.md5(b"data").hexdigest()
sha1_digest = hashlib.sha1(b"data").hexdigest()

# CRYPTO-004: signature
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

key = ec.generate_private_key(ec.SECP256R1())
signature = key.sign(b"message", ec.ECDSA(hashlib.sha256()))

# CRYPTO-003: ECDH
from cryptography.hazmat.primitives.asymmetric import ec as ec2  # noqa: E402

private = ec2.generate_private_key(ec2.SECP256R1())
peer = ec2.generate_private_key(ec2.SECP256R1())
shared = private.exchange(ec2.ECDH(), peer.public_key())

# CRYPTO-005: DSA mention
# DSA signing with DSAPrivateKey

# CRYPTO-011: PQC
ML_KEM_768 = "ml-kem-768 implementation"

# CRYPTO-012: LMS
LMS_SIGNING = "lms firmware signing key"

# CRYPTO-001: weak RSA
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

weak_rsa = rsa.generate_private_key(public_exponent=65537, key_size=1024)
