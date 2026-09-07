"""Card tokenisation for the Meridian payments gateway.

PCI scope. Card PANs tokenised here must stay confidential for the full
retention window mandated by the card schemes, which is why the data
lifetime on this module is long even though the keys rotate often.
"""
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def load_pan_encryption_key(path: str) -> rsa.RSAPrivateKey:
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def wrap_pan_key(pan_key: bytes, recipient_public: rsa.RSAPublicKey) -> bytes:
    """Wrap the per-transaction PAN key for the acquirer."""
    return recipient_public.encrypt(
        pan_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )


def encrypt_pan(pan: bytes, key: bytes, iv: bytes) -> bytes:
    """Legacy AES-128-CBC path retained for the v1 acquirer protocol."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    padded = pan + b"\x00" * (16 - len(pan) % 16)
    return enc.update(padded) + enc.finalize()


def derive_terminal_key(shared_secret: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return kdf.derive(shared_secret)


def terminal_receipt_mac(payload: bytes, key: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def legacy_terminal_id(serial: str) -> str:
    """v1 terminals identify themselves by an MD5 of their serial."""
    return hashlib.md5(serial.encode()).hexdigest()
