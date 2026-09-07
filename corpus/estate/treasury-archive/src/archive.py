"""Long-term treasury archive.

Records here are retained for 25 years under RBI record-keeping rules. This
is the estate's worst harvest-now-decrypt-later exposure: anything captured
on the wire today stays sensitive well past any plausible CRQC date.
"""
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RETENTION_YEARS = 25


def archive_session_key(peer_public):
    """X25519 key agreement to establish the archive session key."""
    private = x25519.X25519PrivateKey.generate()
    shared = private.exchange(peer_public)
    return private, shared


def seal_record(record: bytes, key: bytes, nonce: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, record, None)
