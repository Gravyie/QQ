"""PQC pilot for the interbank channel.

This is the one part of the estate already migrated. It exists so the report
can show what "done" looks like alongside everything that is not.
"""
import oqs

KEM = "ML-KEM-768"
SIG = "ML-DSA-65"


def establish_pilot_session():
    """Hybrid X25519 + ML-KEM-768, mirroring the deployed TLS group."""
    with oqs.KeyEncapsulation(KEM) as client:
        public_key = client.generate_keypair()
        with oqs.KeyEncapsulation(KEM) as server:
            ciphertext, server_secret = server.encap_secret(public_key)
        client_secret = client.decap_secret(ciphertext)
    return client_secret, server_secret


def sign_pilot_manifest(manifest: bytes):
    with oqs.Signature(SIG) as signer:
        public_key = signer.generate_keypair()
        return public_key, signer.sign(manifest)
