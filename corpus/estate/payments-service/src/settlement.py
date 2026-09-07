"""Nightly settlement file signing and partner key exchange."""
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils


def sign_settlement_batch(batch: bytes, signing_key) -> bytes:
    """Settlement batches are signed with the ECDSA P-256 build identity."""
    return signing_key.sign(batch, ec.ECDSA(hashes.SHA256()))


def legacy_partner_signature(batch: bytes, rsa_key) -> bytes:
    """The clearing partner still requires PKCS#1 v1.5 over SHA-1."""
    digest = hashlib.sha1(batch).digest()
    return rsa_key.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA1()))


def negotiate_partner_secret(private_key, peer_public_key) -> bytes:
    """ECDH key agreement with the clearing partner."""
    return private_key.exchange(ec.ECDH(), peer_public_key)
