"""Knowledge-base resolution tests.

The resolver is the foundation of every downstream number: if a cipher-suite
string resolves to the wrong primitive, the risk score, the Mosca verdict, and
the CBOM entry are all wrong together. These cases are drawn from real
nginx/Apache/sshd/OpenSSL output and real X.509 signature-algorithm names.
"""
from __future__ import annotations

import pytest

from atlas.knowledge_base import (ALGORITHMS, canonical_algorithm, decompose,
                                  extract_mode, extract_padding, stats)

# (raw string, expected canonical name, expected quantum impact)
RESOLUTION_CASES = [
    # --- bare algorithms with parameters ---
    ("RSA", "RSA", "shor_broken"),
    ("RSA-2048", "RSA", "shor_broken"),
    ("RSA-4096", "RSA", "shor_broken"),
    ("rsa_2048", "RSA", "shor_broken"),
    ("AES-256-GCM", "AES-256", "classical_ok"),
    ("aes-128-cbc", "AES-128", "grover"),
    ("AES256", "AES-256", "classical_ok"),
    ("3DES", "3DES", "grover"),
    ("DES-EDE3-CBC", "3DES", "grover"),
    ("ChaCha20-Poly1305", "ChaCha20", "classical_ok"),

    # --- X.509 signature algorithm names, as cryptography reports them ---
    ("sha256WithRSAEncryption", "RSA", "shor_broken"),
    ("sha384WithRSAEncryption", "RSA", "shor_broken"),
    ("sha1WithRSAEncryption", "SHA-1", "broken_classically"),
    ("md5WithRSAEncryption", "MD5", "broken_classically"),
    ("ecdsa-with-SHA256", "ECDSA", "shor_broken"),
    ("ecdsa-with-SHA384", "ECDSA-P384", "shor_broken"),
    ("ed25519", "Ed25519", "shor_broken"),
    ("dsa-with-SHA256", "DSA", "shor_broken"),

    # --- curve names ---
    ("prime256v1", "ECDSA-P256", "shor_broken"),
    ("secp384r1", "ECDSA-P384", "shor_broken"),
    ("secp521r1", "ECDSA-P521", "shor_broken"),
    ("curve25519", "X25519", "shor_broken"),

    # --- IANA-style TLS suites ---
    ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDH", "shor_broken"),
    ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDH", "shor_broken"),
    ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DH", "shor_broken"),
    ("TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", "shor_broken"),
    ("TLS_AES_128_GCM_SHA256", "AES-128", "grover"),
    ("TLS_AES_256_GCM_SHA384", "AES-256", "classical_ok"),
    ("TLS_RSA_WITH_RC4_128_SHA", "RC4", "broken_classically"),
    ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "3DES", "grover"),

    # --- OpenSSL suite spellings, straight out of nginx ssl_ciphers ---
    ("ECDHE-RSA-AES128-SHA256", "ECDH", "shor_broken"),
    ("ECDHE-ECDSA-AES256-GCM-SHA384", "ECDH", "shor_broken"),
    ("DHE-RSA-AES128-SHA", "DH", "shor_broken"),
    ("AES128-SHA", "AES-128", "grover"),
    ("AES256-SHA256", "AES-256", "classical_ok"),
    ("DES-CBC3-SHA", "3DES", "grover"),
    ("RC4-SHA", "RC4", "broken_classically"),
    ("RC4-MD5", "RC4", "broken_classically"),
    ("ECDHE-RSA-AES256-SHA384", "ECDH", "shor_broken"),

    # --- SSH algorithm names, straight out of sshd_config ---
    ("aes256-gcm@openssh.com", "AES-256", "classical_ok"),
    ("aes128-ctr", "AES-128", "grover"),
    ("aes256-ctr", "AES-256", "classical_ok"),
    ("3des-cbc", "3DES", "grover"),
    ("curve25519-sha256", "X25519", "shor_broken"),
    ("ecdh-sha2-nistp256", "ECDH", "shor_broken"),
    ("diffie-hellman-group14-sha1", "Diffie-Hellman", "shor_broken"),
    ("sntrup761x25519-sha512", "sntrup761x25519", "pq_safe"),
    ("sntrup761x25519-sha512@openssh.com", "sntrup761x25519", "pq_safe"),
    ("mlkem768x25519-sha256", "mlkem768x25519", "pq_safe"),

    # --- protocol versions ---
    ("TLSv1", "TLSv1.0", "broken_classically"),
    ("TLSv1.1", "TLSv1.1", "broken_classically"),
    ("TLSv1.2", "TLSv1.2", "shor_broken"),
    ("TLSv1.3", "TLSv1.3", "shor_broken"),
    ("SSLv3", "SSLv3", "broken_classically"),
    ("SSLv2", "SSLv2", "broken_classically"),

    # --- post-quantum ---
    ("ML-KEM-768", "ML-KEM-768", "pq_safe"),
    ("ML-DSA-65", "ML-DSA-65", "pq_safe"),
    ("kyber768", "Kyber", "pq_safe"),
    ("dilithium3", "Dilithium", "pq_safe"),
    ("X25519MLKEM768", "X25519MLKEM768", "pq_safe"),
    ("X25519Kyber768Draft00", "X25519Kyber768", "pq_safe"),
    ("SLH-DSA-128s", "SLH-DSA-128s", "pq_safe"),
    ("Falcon-512", "Falcon-512", "pq_safe"),

    # --- algorithms already broken, or never safe ---
    ("MD5", "MD5", "broken_classically"),
    ("SHA-1", "SHA-1", "broken_classically"),
    ("sha1", "SHA-1", "broken_classically"),
    ("DES", "DES", "broken_classically"),
    ("SIKE", "SIKE", "broken_classically"),
    ("Rainbow", "Rainbow", "broken_classically"),

    # --- hashes and KDFs ---
    ("SHA-256", "SHA-256", "classical_ok"),
    ("sha512", "SHA-512", "classical_ok"),
    ("SHAKE256", "SHAKE256", "classical_ok"),
    ("SHA3-256", "SHA-3-256", "classical_ok"),
    ("argon2id", "Argon2", "classical_ok"),
    ("PBKDF2", "PBKDF2", "classical_ok"),
    ("hmac-sha2-256", "HMAC", "classical_ok"),
]


@pytest.mark.parametrize("raw,expected_name,expected_impact", RESOLUTION_CASES)
def test_resolution(raw, expected_name, expected_impact):
    canon, entry = canonical_algorithm(raw)
    assert entry is not None, f"{raw!r} did not resolve to any knowledge-base entry"
    assert canon == expected_name, f"{raw!r} resolved to {canon!r}, expected {expected_name!r}"
    assert entry["impact"] == expected_impact, (
        f"{raw!r} -> {canon!r} has impact {entry['impact']!r}, expected {expected_impact!r}")


def test_unrecognised_returns_none():
    """Unknown strings must return None, never a wrong-but-plausible match."""
    for raw in ("totally-made-up-cipher", "", "   ", "zzz999"):
        _, entry = canonical_algorithm(raw)
        assert entry is None, f"{raw!r} should not resolve"


def test_shake_not_matched_as_sha():
    """The guarded substring match must not let SHA swallow SHAKE."""
    canon, _ = canonical_algorithm("SHAKE128")
    assert canon == "SHAKE128"


def test_weakest_link_precedence():
    """A broken component outranks a Shor-broken key exchange."""
    # ECDHE (shor) + RC4 (already broken) -> RC4 must win.
    canon, entry = canonical_algorithm("ECDHE-RSA-RC4-SHA")
    assert canon == "RC4"
    assert entry["impact"] == "broken_classically"
    # ECDHE + AES-256-GCM: nothing broken, so the Shor-vulnerable KX wins.
    canon, entry = canonical_algorithm("ECDHE-RSA-AES256-GCM-SHA384")
    assert canon == "ECDH"
    assert entry["impact"] == "shor_broken"


def test_mode_extraction():
    assert extract_mode("AES-256-GCM") == "GCM"
    assert extract_mode("aes-128-cbc") == "CBC"
    assert extract_mode("AES-192-ECB") == "ECB"
    assert extract_mode("RSA-OAEP") is None
    assert extract_mode("aes128-ctr") == "CTR"


def test_padding_extraction():
    assert extract_padding("RSA-OAEP") == "OAEP"
    assert extract_padding("RSA-PKCS1") == "PKCS1"
    assert extract_padding("AES-256-GCM") is None


def test_every_entry_is_well_formed():
    """Every knowledge-base entry must carry the fields downstream code reads."""
    required = {"impact", "family", "primitive", "classical_bits", "pq_bits",
                "nist_pq_level"}
    valid_impacts = {"shor_broken", "grover", "classical_ok", "pq_safe",
                     "broken_classically"}
    valid_primitives = {"ae", "block-cipher", "stream-cipher", "hash", "kem",
                        "key-agree", "mac", "pke", "signature", "xof", "drbg",
                        "kdf", "combiner", "other", "unknown"}
    for name, entry in ALGORITHMS.items():
        missing = required - entry.keys()
        assert not missing, f"{name} missing fields: {missing}"
        assert entry["impact"] in valid_impacts, f"{name} bad impact {entry['impact']}"
        assert entry["primitive"] in valid_primitives, (
            f"{name} bad primitive {entry['primitive']}")
        assert isinstance(entry["classical_bits"], int)
        assert isinstance(entry["pq_bits"], int)


def test_pq_safe_entries_retain_strength():
    """A pq_safe algorithm must not claim zero post-quantum strength."""
    for name, entry in ALGORITHMS.items():
        if entry["impact"] == "pq_safe":
            assert entry["pq_bits"] >= 128, f"{name} claims pq_safe with {entry['pq_bits']} bits"
            assert entry["nist_pq_level"] >= 1, f"{name} pq_safe but NIST level 0"


def test_shor_broken_entries_have_zero_pq_bits():
    """Shor reduces asymmetric strength to nothing; the data must say so."""
    for name, entry in ALGORITHMS.items():
        if entry["impact"] == "shor_broken":
            assert entry["pq_bits"] == 0, (
                f"{name} is shor_broken but claims {entry['pq_bits']} pq bits")


def test_grover_halves_symmetric_strength():
    """Grover gives a square-root speedup: pq_bits should be about half."""
    for name, entry in ALGORITHMS.items():
        if entry["impact"] == "grover" and entry["primitive"] in (
                "block-cipher", "stream-cipher"):
            expected = entry["classical_bits"] // 2
            assert entry["pq_bits"] == expected, (
                f"{name}: {entry['classical_bits']} classical bits should give "
                f"{expected} pq bits, entry says {entry['pq_bits']}")


def test_stats_shape():
    s = stats()
    assert s["algorithms"] == len(ALGORITHMS)
    assert sum(s["by_impact"].values()) == len(ALGORITHMS)
    assert sum(s["by_primitive"].values()) == len(ALGORITHMS)


# ---------------------------------------------------------------------------
# Cipher-suite decomposition
# ---------------------------------------------------------------------------
# The resolver scores a suite on its weakest component, but an analyst needs to
# see that the other components were considered rather than silently dropped.
# (suite, expected {role: algorithm})
DECOMPOSE_CASES = [
    ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
     {"key exchange": "ECDH", "authentication": "RSA",
      "bulk cipher": "AES-128", "mac": "SHA-1"}),
    ("TLS_RSA_WITH_3DES_EDE_CBC_SHA",
     {"authentication": "RSA", "bulk cipher": "3DES", "mac": "SHA-1"}),
    ("ECDHE-RSA-AES256-GCM-SHA384",
     {"key exchange": "ECDH", "authentication": "RSA",
      "bulk cipher": "AES-256", "mac": "SHA-384"}),
    ("TLS_AES_256_GCM_SHA384",
     {"bulk cipher": "AES-256", "mac": "SHA-384"}),
    ("TLS_RSA_WITH_RC4_128_MD5",
     {"authentication": "RSA", "bulk cipher": "RC4", "mac": "MD5"}),
    ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
     {"key exchange": "ECDH", "bulk cipher": "ChaCha20", "mac": "SHA-256"}),
]


@pytest.mark.parametrize("suite,expected", DECOMPOSE_CASES)
def test_decompose_finds_every_component(suite, expected):
    got = {c["role"]: c["name"] for c in decompose(suite)}
    assert got == expected, f"{suite} decomposed to {got}"


@pytest.mark.parametrize("suite,_expected", DECOMPOSE_CASES)
def test_decomposition_marks_the_component_the_model_scored(suite, _expected):
    """The 'scored' flag must agree with canonical_algorithm.

    If these disagreed, the UI would highlight a component the risk engine never
    used — the exact kind of unexplainable number this tool exists to avoid.
    """
    canon, _ = canonical_algorithm(suite)
    comps = decompose(suite)
    flagged = [c["name"] for c in comps if c["weakest"]]
    assert flagged == [canon], f"{suite}: scored {canon}, flagged {flagged}"
    assert comps[0]["name"] == canon, "the scored component must be listed first"


@pytest.mark.parametrize("raw", ["RSA", "AES-256-GCM", "ML-KEM-768", "", "SHA-256"])
def test_decompose_ignores_single_primitives(raw):
    """A bare algorithm is not a suite; returning a one-row table would be noise."""
    assert decompose(raw) == []


def test_decompose_annotates_mac_hash_honestly():
    """SHA-1 as an HMAC hash is not the same finding as SHA-1 in a signature."""
    mac = next(c for c in decompose("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
               if c["role"] == "mac")
    assert mac["name"] == "SHA-1"
    assert "not collision-broken" in (mac["note"] or ""), (
        "the MAC-role caveat must be stated, otherwise this reads as a forgery risk")
    assert not mac["weakest"], "the MAC hash must never be the scored component"
