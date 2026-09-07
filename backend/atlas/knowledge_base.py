"""Cryptographic knowledge base.

Every entry carries the fields needed to emit a spec-correct CycloneDX 1.6
`cryptoProperties.algorithmProperties` block, plus the quantum-impact class and
the performance figures the recommendation engine needs to reason about latency
and cost (not just security).

Field reference
---------------
impact          shor_broken | grover | classical_ok | pq_safe | broken_classically
family          internal grouping used for sensitivity + recommendation fallback
primitive       CycloneDX 1.6 enum: ae|block-cipher|stream-cipher|hash|kem|key-agree
                |mac|pke|signature|xof|drbg|kdf|combiner|other|unknown
oid             ISO/ITU object identifier where one is registered
classical_bits  classical security strength in bits
pq_bits         security strength in bits against a CRQC (Grover halves, Shor -> 0)
nist_pq_level   NIST PQC category 1..5, or 0 when not a PQC algorithm
perf            optional: measured/published cost figures used by the advisor
                  pub_bytes / sig_bytes / ct_bytes  wire cost
                  ops_ms                            reference CPU cost per op
"""
from __future__ import annotations

import re

ALGORITHMS: dict[str, dict] = {
    # ------------------------------------------------------------------
    # Asymmetric: fully broken by Shor's algorithm. pq_bits = 0.
    # ------------------------------------------------------------------
    "RSA": {"impact": "shor_broken", "family": "asymmetric-encryption", "primitive": "pke",
            "oid": "1.2.840.113549.1.1.1", "classical_bits": 112, "pq_bits": 0, "nist_pq_level": 0,
            "bits_basis": "RSA-2048", "nist_status": "legacy",
            "note": "Factoring-based. Shor recovers the private key from the modulus.",
            "perf": {"pub_bytes": 270, "sig_bytes": 256, "ops_ms": 1.4}},
    "RSA-PSS": {"impact": "shor_broken", "family": "signature", "primitive": "signature",
                "oid": "1.2.840.113549.1.1.10", "classical_bits": 112, "pq_bits": 0, "nist_pq_level": 0,
                "bits_basis": "RSA-2048", "nist_status": "legacy", "perf": {"sig_bytes": 256, "ops_ms": 1.4}},
    "RSA-OAEP": {"impact": "shor_broken", "family": "asymmetric-encryption", "primitive": "pke",
                 "oid": "1.2.840.113549.1.1.7", "classical_bits": 112, "pq_bits": 0, "nist_pq_level": 0,
                 "bits_basis": "RSA-2048", "nist_status": "legacy"},
    "RSA-KEM": {"impact": "shor_broken", "family": "kem", "primitive": "kem",
                "classical_bits": 112, "pq_bits": 0, "nist_pq_level": 0,
                "bits_basis": "RSA-2048", "nist_status": "legacy"},
    "DSA": {"impact": "shor_broken", "family": "signature", "primitive": "signature",
            "oid": "1.2.840.10040.4.1", "classical_bits": 112, "pq_bits": 0, "nist_pq_level": 0,
            "bits_basis": "2048-bit p", "nist_status": "legacy", "note": "Withdrawn for new signatures by FIPS 186-5."},
    "ECDSA": {"impact": "shor_broken", "family": "signature", "primitive": "signature",
              "oid": "1.2.840.10045.4.3.2", "classical_bits": 128, "pq_bits": 0, "nist_pq_level": 0,
              "bits_basis": "P-256", "nist_status": "legacy", "note": "Elliptic-curve discrete log falls to Shor.",
              "perf": {"pub_bytes": 65, "sig_bytes": 64, "ops_ms": 0.09}},
    "ECDSA-P256": {"impact": "shor_broken", "family": "signature", "primitive": "signature",
                   "oid": "1.2.840.10045.3.1.7", "classical_bits": 128, "pq_bits": 0, "nist_pq_level": 0,
                   "nist_status": "legacy", "perf": {"pub_bytes": 65, "sig_bytes": 64, "ops_ms": 0.09}},
    "ECDSA-P384": {"impact": "shor_broken", "family": "signature", "primitive": "signature",
                   "oid": "1.3.132.0.34", "classical_bits": 192, "pq_bits": 0, "nist_pq_level": 0,
                   "nist_status": "legacy", "perf": {"pub_bytes": 97, "sig_bytes": 96, "ops_ms": 0.31}},
    "ECDSA-P521": {"impact": "shor_broken", "family": "signature", "primitive": "signature",
                   "oid": "1.3.132.0.35", "classical_bits": 256, "pq_bits": 0, "nist_pq_level": 0,
                   "nist_status": "legacy", "perf": {"pub_bytes": 133, "sig_bytes": 132, "ops_ms": 0.68}},
    "Ed25519": {"impact": "shor_broken", "family": "signature", "primitive": "signature",
                "oid": "1.3.101.112", "classical_bits": 128, "pq_bits": 0, "nist_pq_level": 0,
                "nist_status": "legacy", "perf": {"pub_bytes": 32, "sig_bytes": 64, "ops_ms": 0.05}},
    "Ed448": {"impact": "shor_broken", "family": "signature", "primitive": "signature",
              "oid": "1.3.101.113", "classical_bits": 224, "pq_bits": 0, "nist_pq_level": 0,
              "nist_status": "legacy", "perf": {"pub_bytes": 57, "sig_bytes": 114, "ops_ms": 0.15}},
    "ECDH": {"impact": "shor_broken", "family": "key-agreement", "primitive": "key-agree",
             # id-ecPublicKey. This is the OID that actually appears in the
             # SubjectPublicKeyInfo of a certificate whose key is used for ECDH.
             # The 1.3.132.1.x SECG arc holds specific key-agreement *schemes*
             # (each bound to a particular KDF hash), which is a narrower claim
             # than "this estate uses ECDH" and would be wrong to assert here.
             "oid": "1.2.840.10045.2.1", "classical_bits": 128, "pq_bits": 0, "nist_pq_level": 0,
             "bits_basis": "P-256", "nist_status": "legacy",
             "note": "Harvest-now-decrypt-later applies directly.",
             "perf": {"pub_bytes": 65, "ops_ms": 0.07}},
    "X25519": {"impact": "shor_broken", "family": "key-agreement", "primitive": "key-agree",
               "oid": "1.3.101.110", "classical_bits": 128, "pq_bits": 0, "nist_pq_level": 0,
               "nist_status": "legacy", "perf": {"pub_bytes": 32, "ops_ms": 0.04}},
    "X448": {"impact": "shor_broken", "family": "key-agreement", "primitive": "key-agree",
             "oid": "1.3.101.111", "classical_bits": 224, "pq_bits": 0, "nist_pq_level": 0,
             "nist_status": "legacy", "perf": {"pub_bytes": 56, "ops_ms": 0.12}},
    "DH": {"impact": "shor_broken", "family": "key-agreement", "primitive": "key-agree",
           "oid": "1.2.840.113549.1.3.1", "classical_bits": 112, "pq_bits": 0, "nist_pq_level": 0,
           "bits_basis": "2048-bit group", "nist_status": "legacy", "perf": {"pub_bytes": 256, "ops_ms": 2.1}},
    "Diffie-Hellman": {"impact": "shor_broken", "family": "key-agreement", "primitive": "key-agree",
                       "classical_bits": 112, "pq_bits": 0, "nist_pq_level": 0,
                       "bits_basis": "2048-bit group", "nist_status": "legacy"},
    "ElGamal": {"impact": "shor_broken", "family": "asymmetric-encryption", "primitive": "pke",
                "classical_bits": 112, "pq_bits": 0, "nist_pq_level": 0,
                "bits_basis": "2048-bit group", "nist_status": "legacy"},
    "SM2": {"impact": "shor_broken", "family": "signature", "primitive": "signature",
            "oid": "1.2.156.10197.1.301", "classical_bits": 128, "pq_bits": 0, "nist_pq_level": 0,
            "nist_status": "legacy", "note": "Chinese national EC standard. Same Shor exposure."},
    "GOST": {"impact": "shor_broken", "family": "signature", "primitive": "signature",
             "classical_bits": 128, "pq_bits": 0, "nist_pq_level": 0, "nist_status": "legacy"},
    "SRP": {"impact": "shor_broken", "family": "key-agreement", "primitive": "key-agree",
            "classical_bits": 112, "pq_bits": 0, "nist_pq_level": 0,
            "bits_basis": "2048-bit group", "nist_status": "legacy"},

    # ------------------------------------------------------------------
    # Symmetric ciphers. Grover halves the effective key length.
    # ------------------------------------------------------------------
    "AES": {"impact": "grover", "family": "symmetric-cipher", "primitive": "block-cipher",
            "oid": "2.16.840.1.101.3.4.1", "classical_bits": 128, "pq_bits": 64, "nist_pq_level": 0,
            "bits_basis": "AES-128 assumed", "nist_status": "active",
            "note": "Unqualified AES usage. Confirm the key size: AES-128 drops below the 128-bit floor."},
    "AES-128": {"impact": "grover", "family": "symmetric-cipher", "primitive": "block-cipher",
                "oid": "2.16.840.1.101.3.4.1.2", "classical_bits": 128, "pq_bits": 64, "nist_pq_level": 0,
                "nist_status": "active", "note": "Grover reduces to ~64-bit effective strength."},
    "AES-192": {"impact": "grover", "family": "symmetric-cipher", "primitive": "block-cipher",
                "oid": "2.16.840.1.101.3.4.1.22", "classical_bits": 192, "pq_bits": 96, "nist_pq_level": 0,
                "nist_status": "active"},
    "AES-256": {"impact": "classical_ok", "family": "symmetric-cipher", "primitive": "block-cipher",
                "oid": "2.16.840.1.101.3.4.1.42", "classical_bits": 256, "pq_bits": 128, "nist_pq_level": 0,
                "nist_status": "active", "note": "128-bit post-quantum strength. CNSA 2.0 approved."},
    "ChaCha20": {"impact": "classical_ok", "family": "symmetric-cipher", "primitive": "stream-cipher",
                 "classical_bits": 256, "pq_bits": 128, "nist_pq_level": 0, "nist_status": "active"},
    "Salsa20": {"impact": "classical_ok", "family": "symmetric-cipher", "primitive": "stream-cipher",
                "classical_bits": 256, "pq_bits": 128, "nist_pq_level": 0, "nist_status": "active"},
    "SM4": {"impact": "grover", "family": "symmetric-cipher", "primitive": "block-cipher",
            "classical_bits": 128, "pq_bits": 64, "nist_pq_level": 0, "nist_status": "active"},
    "3DES": {"impact": "grover", "family": "symmetric-cipher", "primitive": "block-cipher",
             "oid": "1.2.840.113549.3.7", "classical_bits": 112, "pq_bits": 56, "nist_pq_level": 0,
             "nist_status": "disallowed", "note": "Disallowed after 2023 by NIST SP 800-131A Rev.2."},
    "DES": {"impact": "broken_classically", "family": "symmetric-cipher", "primitive": "block-cipher",
            "oid": "1.3.14.3.2.7", "classical_bits": 56, "pq_bits": 28, "nist_pq_level": 0,
            "nist_status": "disallowed", "note": "56-bit key. Brute-forced classically since 1998."},
    "Blowfish": {"impact": "grover", "family": "symmetric-cipher", "primitive": "block-cipher",
                 "classical_bits": 128, "pq_bits": 64, "nist_pq_level": 0, "nist_status": "legacy",
                 "note": "64-bit block. Sweet32 birthday collisions past 32GB."},
    "IDEA": {"impact": "grover", "family": "symmetric-cipher", "primitive": "block-cipher",
             "classical_bits": 128, "pq_bits": 64, "nist_pq_level": 0, "nist_status": "legacy"},
    "CAST5": {"impact": "grover", "family": "symmetric-cipher", "primitive": "block-cipher",
              "classical_bits": 128, "pq_bits": 64, "nist_pq_level": 0, "nist_status": "legacy"},
    "RC4": {"impact": "broken_classically", "family": "symmetric-cipher", "primitive": "stream-cipher",
            "oid": "1.2.840.113549.3.4", "classical_bits": 40, "pq_bits": 20, "nist_pq_level": 0,
            "nist_status": "disallowed", "note": "Keystream biases. Prohibited in TLS by RFC 7465."},
    "RC2": {"impact": "broken_classically", "family": "symmetric-cipher", "primitive": "block-cipher",
            "classical_bits": 64, "pq_bits": 32, "nist_pq_level": 0, "nist_status": "disallowed"},
    "ARIA-128": {"impact": "grover", "family": "symmetric-cipher", "primitive": "block-cipher",
                 "classical_bits": 128, "pq_bits": 64, "nist_pq_level": 0, "nist_status": "active"},
    "ARIA-256": {"impact": "classical_ok", "family": "symmetric-cipher", "primitive": "block-cipher",
                 "classical_bits": 256, "pq_bits": 128, "nist_pq_level": 0, "nist_status": "active"},
    "SEED": {"impact": "grover", "family": "symmetric-cipher", "primitive": "block-cipher",
             "classical_bits": 128, "pq_bits": 64, "nist_pq_level": 0, "nist_status": "active"},
    "Camellia-128": {"impact": "grover", "family": "symmetric-cipher", "primitive": "block-cipher",
                     "classical_bits": 128, "pq_bits": 64, "nist_pq_level": 0, "nist_status": "active"},
    "Camellia-256": {"impact": "classical_ok", "family": "symmetric-cipher", "primitive": "block-cipher",
                     "classical_bits": 256, "pq_bits": 128, "nist_pq_level": 0, "nist_status": "active"},

    # ------------------------------------------------------------------
    # Hashes, MACs, KDFs
    # ------------------------------------------------------------------
    "MD5": {"impact": "broken_classically", "family": "hash", "primitive": "hash",
            "oid": "1.2.840.113549.2.5", "classical_bits": 18, "pq_bits": 9, "nist_pq_level": 0,
            "nist_status": "disallowed", "note": "Chosen-prefix collisions in seconds on a laptop."},
    "SHA-1": {"impact": "broken_classically", "family": "hash", "primitive": "hash",
              "oid": "1.3.14.3.2.26", "classical_bits": 63, "pq_bits": 32, "nist_pq_level": 0,
              "nist_status": "disallowed", "note": "SHAttered 2017, chosen-prefix 2020. NIST retires 2030."},
    "SHA-224": {"impact": "grover", "family": "hash", "primitive": "hash",
                "oid": "2.16.840.1.101.3.4.2.4", "classical_bits": 112, "pq_bits": 74,
                "nist_pq_level": 0, "nist_status": "active"},
    "SHA-256": {"impact": "classical_ok", "family": "hash", "primitive": "hash",
                "oid": "2.16.840.1.101.3.4.2.1", "classical_bits": 128, "pq_bits": 85,
                "nist_pq_level": 0, "nist_status": "active"},
    "SHA-384": {"impact": "classical_ok", "family": "hash", "primitive": "hash",
                "oid": "2.16.840.1.101.3.4.2.2", "classical_bits": 192, "pq_bits": 128,
                "nist_pq_level": 0, "nist_status": "active", "note": "CNSA 2.0 minimum for hashing."},
    "SHA-512": {"impact": "classical_ok", "family": "hash", "primitive": "hash",
                "oid": "2.16.840.1.101.3.4.2.3", "classical_bits": 256, "pq_bits": 170,
                "nist_pq_level": 0, "nist_status": "active"},
    "SHA-3-256": {"impact": "classical_ok", "family": "hash", "primitive": "hash",
                  "oid": "2.16.840.1.101.3.4.2.8", "classical_bits": 128, "pq_bits": 85,
                  "nist_pq_level": 0, "nist_status": "active"},
    "SHA-3-512": {"impact": "classical_ok", "family": "hash", "primitive": "hash",
                  "oid": "2.16.840.1.101.3.4.2.10", "classical_bits": 256, "pq_bits": 170,
                  "nist_pq_level": 0, "nist_status": "active"},
    "BLAKE2b": {"impact": "classical_ok", "family": "hash", "primitive": "hash",
                "classical_bits": 256, "pq_bits": 170, "nist_pq_level": 0, "nist_status": "active"},
    "BLAKE2s": {"impact": "classical_ok", "family": "hash", "primitive": "hash",
                "classical_bits": 128, "pq_bits": 85, "nist_pq_level": 0, "nist_status": "active"},
    "BLAKE3": {"impact": "classical_ok", "family": "hash", "primitive": "hash",
               "classical_bits": 128, "pq_bits": 85, "nist_pq_level": 0, "nist_status": "active"},
    "RIPEMD-160": {"impact": "grover", "family": "hash", "primitive": "hash",
                   "classical_bits": 80, "pq_bits": 53, "nist_pq_level": 0, "nist_status": "legacy"},
    "SHAKE128": {"impact": "classical_ok", "family": "hash", "primitive": "xof",
                 "oid": "2.16.840.1.101.3.4.2.11", "classical_bits": 128, "pq_bits": 85,
                 "nist_pq_level": 0, "nist_status": "active"},
    "SHAKE256": {"impact": "classical_ok", "family": "hash", "primitive": "xof",
                 "oid": "2.16.840.1.101.3.4.2.12", "classical_bits": 256, "pq_bits": 170,
                 "nist_pq_level": 0, "nist_status": "active"},
    "HMAC": {"impact": "classical_ok", "family": "mac", "primitive": "mac",
             "classical_bits": 128, "pq_bits": 128, "nist_pq_level": 0,
             "bits_basis": "128-bit key assumed", "nist_status": "active",
             "note": "Symmetric MAC. No quantum key-recovery advantage beyond Grover on the key."},
    "CMAC": {"impact": "classical_ok", "family": "mac", "primitive": "mac",
             "classical_bits": 128, "pq_bits": 64, "nist_pq_level": 0, "nist_status": "active"},
    "Poly1305": {"impact": "classical_ok", "family": "mac", "primitive": "mac",
                 "classical_bits": 128, "pq_bits": 128, "nist_pq_level": 0, "nist_status": "active"},
    "GMAC": {"impact": "classical_ok", "family": "mac", "primitive": "mac",
             "classical_bits": 128, "pq_bits": 64, "nist_pq_level": 0, "nist_status": "active"},
    "PBKDF2": {"impact": "classical_ok", "family": "kdf", "primitive": "kdf",
               "oid": "1.2.840.113549.1.5.12", "classical_bits": 128, "pq_bits": 64,
               "nist_pq_level": 0, "nist_status": "active",
               "note": "Iteration count is the real control. NIST floor is 210k for SHA-256."},
    "scrypt": {"impact": "classical_ok", "family": "kdf", "primitive": "kdf",
               "classical_bits": 128, "pq_bits": 64, "nist_pq_level": 0, "nist_status": "active"},
    "bcrypt": {"impact": "classical_ok", "family": "kdf", "primitive": "kdf",
               "classical_bits": 128, "pq_bits": 64, "nist_pq_level": 0, "nist_status": "active",
               "note": "72-byte input truncation. Prefer Argon2id for new designs."},
    "Argon2": {"impact": "classical_ok", "family": "kdf", "primitive": "kdf",
               "classical_bits": 128, "pq_bits": 64, "nist_pq_level": 0, "nist_status": "active"},
    "HKDF": {"impact": "classical_ok", "family": "kdf", "primitive": "kdf",
             "classical_bits": 128, "pq_bits": 128, "nist_pq_level": 0, "nist_status": "active"},
    "HKDF-SHA256": {"impact": "classical_ok", "family": "kdf", "primitive": "kdf",
                    "classical_bits": 128, "pq_bits": 128, "nist_pq_level": 0, "nist_status": "active"},
    "HKDF-SHA384": {"impact": "classical_ok", "family": "kdf", "primitive": "kdf",
                    "classical_bits": 192, "pq_bits": 128, "nist_pq_level": 0, "nist_status": "active"},
    "HKDF-SHA512": {"impact": "classical_ok", "family": "kdf", "primitive": "kdf",
                    "classical_bits": 256, "pq_bits": 128, "nist_pq_level": 0, "nist_status": "active"},

    # ------------------------------------------------------------------
    # Post-quantum standards
    # ------------------------------------------------------------------
    "ML-KEM": {"impact": "pq_safe", "family": "kem", "primitive": "kem",
               "oid": "2.16.840.1.101.3.4.4", "classical_bits": 192, "pq_bits": 192,
               "nist_pq_level": 3, "nist_status": "FIPS 203",
               "note": "NIST module-lattice KEM, standardised August 2024 (was Kyber)."},
    "ML-KEM-512": {"impact": "pq_safe", "family": "kem", "primitive": "kem",
                   "oid": "2.16.840.1.101.3.4.4.1", "classical_bits": 128, "pq_bits": 128,
                   "nist_pq_level": 1, "nist_status": "FIPS 203",
                   "perf": {"pub_bytes": 800, "ct_bytes": 768, "ops_ms": 0.03}},
    "ML-KEM-768": {"impact": "pq_safe", "family": "kem", "primitive": "kem",
                   "oid": "2.16.840.1.101.3.4.4.2", "classical_bits": 192, "pq_bits": 192,
                   "nist_pq_level": 3, "nist_status": "FIPS 203",
                   "note": "Recommended default. Used in the deployed X25519MLKEM768 TLS group.",
                   "perf": {"pub_bytes": 1184, "ct_bytes": 1088, "ops_ms": 0.05}},
    "ML-KEM-1024": {"impact": "pq_safe", "family": "kem", "primitive": "kem",
                    "oid": "2.16.840.1.101.3.4.4.3", "classical_bits": 256, "pq_bits": 256,
                    "nist_pq_level": 5, "nist_status": "FIPS 203",
                    "note": "CNSA 2.0 mandates this level for national-security systems.",
                    "perf": {"pub_bytes": 1568, "ct_bytes": 1568, "ops_ms": 0.08}},
    "ML-DSA": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
               "oid": "2.16.840.1.101.3.4.3.17", "classical_bits": 192, "pq_bits": 192,
               "nist_pq_level": 3, "nist_status": "FIPS 204",
               "note": "NIST module-lattice signature, standardised August 2024 (was Dilithium)."},
    "ML-DSA-44": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
                  "oid": "2.16.840.1.101.3.4.3.17", "classical_bits": 128, "pq_bits": 128,
                  "nist_pq_level": 2, "nist_status": "FIPS 204",
                  "perf": {"pub_bytes": 1312, "sig_bytes": 2420, "ops_ms": 0.33}},
    "ML-DSA-65": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
                  "oid": "2.16.840.1.101.3.4.3.18", "classical_bits": 192, "pq_bits": 192,
                  "nist_pq_level": 3, "nist_status": "FIPS 204",
                  "perf": {"pub_bytes": 1952, "sig_bytes": 3309, "ops_ms": 0.52}},
    "ML-DSA-87": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
                  "oid": "2.16.840.1.101.3.4.3.19", "classical_bits": 256, "pq_bits": 256,
                  "nist_pq_level": 5, "nist_status": "FIPS 204",
                  "note": "CNSA 2.0 level for signatures.",
                  "perf": {"pub_bytes": 2592, "sig_bytes": 4627, "ops_ms": 0.79}},
    "SLH-DSA": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
                "oid": "2.16.840.1.101.3.4.3.20", "classical_bits": 128, "pq_bits": 128,
                "nist_pq_level": 1, "nist_status": "FIPS 205",
                "note": "Hash-based and stateless (was SPHINCS+). Conservative choice for firmware roots."},
    "SLH-DSA-128s": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
                     "classical_bits": 128, "pq_bits": 128, "nist_pq_level": 1, "nist_status": "FIPS 205",
                     "perf": {"pub_bytes": 32, "sig_bytes": 7856, "ops_ms": 240.0}},
    "SLH-DSA-128f": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
                     "classical_bits": 128, "pq_bits": 128, "nist_pq_level": 1, "nist_status": "FIPS 205",
                     "perf": {"pub_bytes": 32, "sig_bytes": 17088, "ops_ms": 11.0}},
    "SLH-DSA-256s": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
                     "classical_bits": 256, "pq_bits": 256, "nist_pq_level": 5, "nist_status": "FIPS 205",
                     "perf": {"pub_bytes": 64, "sig_bytes": 29792, "ops_ms": 600.0}},
    "SLH-DSA-256f": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
                     "classical_bits": 256, "pq_bits": 256, "nist_pq_level": 5, "nist_status": "FIPS 205",
                     "perf": {"pub_bytes": 64, "sig_bytes": 49856, "ops_ms": 29.0}},
    "FN-DSA": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
               "classical_bits": 128, "pq_bits": 128, "nist_pq_level": 1,
               "nist_status": "FIPS 206 draft",
               "note": "Falcon. Compact signatures, but floating-point sampling needs side-channel care."},
    "Falcon-512": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
                   "classical_bits": 128, "pq_bits": 128, "nist_pq_level": 1,
                   "nist_status": "FIPS 206 draft", "perf": {"pub_bytes": 897, "sig_bytes": 666, "ops_ms": 2.6}},
    "Falcon-1024": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
                    "classical_bits": 256, "pq_bits": 256, "nist_pq_level": 5,
                    "nist_status": "FIPS 206 draft", "perf": {"pub_bytes": 1793, "sig_bytes": 1280, "ops_ms": 5.2}},
    "Kyber": {"impact": "pq_safe", "family": "kem", "primitive": "kem", "classical_bits": 192,
              "pq_bits": 192, "nist_pq_level": 3, "nist_status": "superseded by ML-KEM",
              "note": "Pre-standard name. Wire format differs from FIPS 203: verify interop."},
    "Dilithium": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
                  "classical_bits": 192, "pq_bits": 192, "nist_pq_level": 3,
                  "nist_status": "superseded by ML-DSA",
                  "note": "Pre-standard name. Not wire-compatible with FIPS 204."},
    "SPHINCS+": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
                 "classical_bits": 128, "pq_bits": 128, "nist_pq_level": 1,
                 "nist_status": "superseded by SLH-DSA"},
    "CRYSTALS-Kyber": {"impact": "pq_safe", "family": "kem", "primitive": "kem",
                       "classical_bits": 192, "pq_bits": 192, "nist_pq_level": 3,
                       "nist_status": "superseded by ML-KEM"},
    "CRYSTALS-Dilithium": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
                           "classical_bits": 192, "pq_bits": 192, "nist_pq_level": 3,
                           "nist_status": "superseded by ML-DSA"},
    "Classic McEliece": {"impact": "pq_safe", "family": "kem", "primitive": "kem",
                         "classical_bits": 128, "pq_bits": 128, "nist_pq_level": 1,
                         "nist_status": "round-4 alternate",
                         "note": "261KB public keys. Viable only where keys are pre-distributed.",
                         "perf": {"pub_bytes": 261120, "ct_bytes": 128, "ops_ms": 0.06}},
    "HQC": {"impact": "pq_safe", "family": "kem", "primitive": "kem", "classical_bits": 128,
            "pq_bits": 128, "nist_pq_level": 1, "nist_status": "selected March 2025",
            "note": "Code-based backup KEM, chosen so PQC does not rest on lattices alone.",
            "perf": {"pub_bytes": 2249, "ct_bytes": 4497, "ops_ms": 0.29}},
    "BIKE": {"impact": "pq_safe", "family": "kem", "primitive": "kem", "classical_bits": 128,
             "pq_bits": 128, "nist_pq_level": 1, "nist_status": "round-4 alternate"},
    "SIKE": {"impact": "broken_classically", "family": "kem", "primitive": "kem",
             "classical_bits": 0, "pq_bits": 0, "nist_pq_level": 0, "nist_status": "broken 2022",
             "note": "Castryck-Decuypere torsion attack recovers keys in about an hour. Never deploy."},
    "Rainbow": {"impact": "broken_classically", "family": "signature", "primitive": "signature",
                "classical_bits": 0, "pq_bits": 0, "nist_pq_level": 0, "nist_status": "broken 2022",
                "note": "Beullens attack breaks the level-1 parameter set in a weekend."},
    "NewHope": {"impact": "pq_safe", "family": "kem", "primitive": "kem", "classical_bits": 128,
                "pq_bits": 128, "nist_pq_level": 1, "nist_status": "superseded by ML-KEM"},
    "XMSS": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
             "classical_bits": 128, "pq_bits": 128, "nist_pq_level": 1, "nist_status": "SP 800-208",
             "note": "Stateful. Reusing a one-time key index destroys security: needs HSM state handling.",
             # XMSS-SHA2_10_256: 64-byte public key, 2500-byte signature. Sizes are
             # parameter-set dependent (tree height and Winternitz w), so these are
             # the SP 800-208 reference set rather than a universal figure.
             "perf": {"pub_bytes": 64, "sig_bytes": 2500, "ops_ms": 3.5,
                      "perf_basis": "XMSS-SHA2_10_256; other parameter sets differ"}},
    "LMS": {"impact": "pq_safe", "family": "signature", "primitive": "signature",
            "classical_bits": 128, "pq_bits": 128, "nist_pq_level": 1, "nist_status": "SP 800-208",
            "note": "Stateful hash-based. Approved for firmware signing where state is controlled.",
            # LMS_SHA256_M32_H10 with LMOTS_SHA256_N32_W8: 56-byte public key,
            # 1452-byte signature (4 + 1124 LM-OTS + 4 + 10x32 auth path).
            # HSS multi-level trees are substantially larger.
            "perf": {"pub_bytes": 56, "sig_bytes": 1452, "ops_ms": 1.2,
                     "perf_basis": "LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W8"}},

    # ------------------------------------------------------------------
    # Hybrid TLS 1.3 groups and composite certificate algorithms
    # ------------------------------------------------------------------
    "X25519MLKEM768": {"impact": "pq_safe", "family": "kem", "primitive": "combiner",
                       "classical_bits": 192, "pq_bits": 192, "nist_pq_level": 3,
                       "nist_status": "hybrid, RFC 9794 style",
                       "note": "Codepoint 0x11ec. Default in Chrome and Cloudflare edge since 2024.",
                       "perf": {"pub_bytes": 1216, "ct_bytes": 1120, "ops_ms": 0.09}},
    "X25519Kyber768": {"impact": "pq_safe", "family": "kem", "primitive": "combiner",
                       "classical_bits": 192, "pq_bits": 192, "nist_pq_level": 3,
                       "nist_status": "hybrid, pre-standard",
                       "note": "Codepoint 0x6399. Being retired in favour of X25519MLKEM768."},
    "SecP256r1MLKEM768": {"impact": "pq_safe", "family": "kem", "primitive": "combiner",
                          "classical_bits": 192, "pq_bits": 192, "nist_pq_level": 3,
                          "nist_status": "hybrid", "note": "For FIPS-constrained stacks that cannot use X25519.",
                          # P-256 uncompressed point (65) + ML-KEM-768 pk 1184 / ct 1088.
                          "perf": {"pub_bytes": 1249, "ct_bytes": 1153, "ops_ms": 0.14}},
    "SecP384r1MLKEM1024": {"impact": "pq_safe", "family": "kem", "primitive": "combiner",
                           "classical_bits": 256, "pq_bits": 256, "nist_pq_level": 5,
                           "nist_status": "hybrid", "note": "CNSA 2.0 aligned hybrid group.",
                           # P-384 uncompressed point (97) + ML-KEM-1024 pk 1568 / ct 1568.
                           "perf": {"pub_bytes": 1665, "ct_bytes": 1665, "ops_ms": 0.42}},
    "ML-DSA-65+ECDSA-P256": {"impact": "pq_safe", "family": "signature", "primitive": "combiner",
                             "classical_bits": 192, "pq_bits": 192, "nist_pq_level": 3,
                             "nist_status": "composite, draft-ietf-lamps-pq-composite-sigs",
                             "note": "Both signatures must verify. Survives a break in either algorithm."},
    "ML-DSA-65+Ed25519": {"impact": "pq_safe", "family": "signature", "primitive": "combiner",
                          "classical_bits": 192, "pq_bits": 192, "nist_pq_level": 3,
                          "nist_status": "composite"},
    "ML-KEM-768+X25519": {"impact": "pq_safe", "family": "kem", "primitive": "combiner",
                          "classical_bits": 192, "pq_bits": 192, "nist_pq_level": 3,
                          "nist_status": "composite KEM"},

    # ------------------------------------------------------------------
    # Protocol versions
    # ------------------------------------------------------------------
    "SSLv2": {"impact": "broken_classically", "family": "protocol", "primitive": "other",
              "classical_bits": 0, "pq_bits": 0, "nist_pq_level": 0, "nist_status": "prohibited",
              "note": "DROWN. Prohibited by RFC 6176."},
    "SSLv3": {"impact": "broken_classically", "family": "protocol", "primitive": "other",
              "classical_bits": 0, "pq_bits": 0, "nist_pq_level": 0, "nist_status": "prohibited",
              "note": "POODLE. Prohibited by RFC 7568."},
    "TLSv1.0": {"impact": "broken_classically", "family": "protocol", "primitive": "other",
                "classical_bits": 64, "pq_bits": 0, "nist_pq_level": 0, "nist_status": "deprecated",
                "note": "Deprecated by RFC 8996. No PQC key exchange possible."},
    "TLSv1.1": {"impact": "broken_classically", "family": "protocol", "primitive": "other",
                "classical_bits": 64, "pq_bits": 0, "nist_pq_level": 0, "nist_status": "deprecated",
                "note": "Deprecated by RFC 8996."},
    "TLSv1.2": {"impact": "shor_broken", "family": "protocol", "primitive": "other",
                "classical_bits": 128, "pq_bits": 0, "nist_pq_level": 0, "nist_status": "active",
                "note": "No standardised hybrid key exchange. PQC migration requires TLS 1.3."},
    "TLSv1.3": {"impact": "shor_broken", "family": "protocol", "primitive": "other",
                "classical_bits": 128, "pq_bits": 0, "nist_pq_level": 0, "nist_status": "active",
                "note": "PQC-ready, but only if a hybrid group is actually negotiated."},
    "TLS": {"impact": "shor_broken", "family": "protocol", "primitive": "other",
            "classical_bits": 128, "pq_bits": 0, "nist_pq_level": 0, "nist_status": "active"},
    "SSH-2": {"impact": "shor_broken", "family": "protocol", "primitive": "other",
              "classical_bits": 128, "pq_bits": 0, "nist_pq_level": 0, "nist_status": "active",
              "note": "OpenSSH 9.x offers sntrup761x25519 and mlkem768x25519 hybrid KEX."},
    "IKEv2": {"impact": "shor_broken", "family": "protocol", "primitive": "other",
              "classical_bits": 128, "pq_bits": 0, "nist_pq_level": 0, "nist_status": "active",
              "note": "RFC 9370 multiple key exchange allows adding a PQC round."},
    "sntrup761x25519": {"impact": "pq_safe", "family": "kem", "primitive": "combiner",
                        "classical_bits": 128, "pq_bits": 128, "nist_pq_level": 1,
                        "nist_status": "hybrid SSH KEX",
                        "note": "OpenSSH default since 9.0. NTRU Prime plus X25519."},
    "mlkem768x25519": {"impact": "pq_safe", "family": "kem", "primitive": "combiner",
                       "classical_bits": 192, "pq_bits": 192, "nist_pq_level": 3,
                       "nist_status": "hybrid SSH KEX", "note": "OpenSSH 10 default."},
}

# Aliases resolved before any suffix stripping.
ALIASES = {
    "MLKEM768X25519": "mlkem768x25519",
    "SNTRUP761X25519-SHA512": "sntrup761x25519",
    "SNTRUP761X25519": "sntrup761x25519",
    "X25519MLKEM768DRAFT00": "X25519MLKEM768",
    "X25519KYBER768DRAFT00": "X25519Kyber768",
    "MLKEM768X25519SHA256": "mlkem768x25519",
    "SECP256R1MLKEM768": "SecP256r1MLKEM768",
    "SECP384R1MLKEM1024": "SecP384r1MLKEM1024",
    "TLS1.0": "TLSv1.0", "TLS1.1": "TLSv1.1", "TLS1.2": "TLSv1.2", "TLS1.3": "TLSv1.3",
    "TLSV1": "TLSv1.0", "TLS-1.0": "TLSv1.0", "TLS-1.1": "TLSv1.1",
    "TLS-1.2": "TLSv1.2", "TLS-1.3": "TLSv1.3",
    "SSLV2": "SSLv2", "SSLV3": "SSLv3", "SSL2": "SSLv2", "SSL3": "SSLv3",
    "SHA1": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256",
    "SHA384": "SHA-384", "SHA512": "SHA-512",
    "SHA3-256": "SHA-3-256", "SHA3-512": "SHA-3-512",
    "DES-EDE3": "3DES", "DES3": "3DES", "TRIPLEDES": "3DES", "DES-EDE3-CBC": "3DES",
    "ARC4": "RC4", "ARCFOUR": "RC4",
    "AES128": "AES-128", "AES192": "AES-192", "AES256": "AES-256",
    "ECDSA-SHA256": "ECDSA", "ECDSA-WITH-SHA256": "ECDSA",
    # OpenSSL / X.509 signature-algorithm spellings. These are what
    # `cryptography` reports as cert.signature_algorithm_oid._name and what
    # appears verbatim in openssl output, so they must resolve to the
    # asymmetric primitive under attack, not the hash.
    "SHA256WITHRSAENCRYPTION": "RSA", "SHA384WITHRSAENCRYPTION": "RSA",
    "SHA512WITHRSAENCRYPTION": "RSA", "SHA224WITHRSAENCRYPTION": "RSA",
    "SHA1WITHRSAENCRYPTION": "SHA-1", "MD5WITHRSAENCRYPTION": "MD5",
    "MD2WITHRSAENCRYPTION": "MD5",
    "ECDSA-WITH-SHA1": "SHA-1", "ECDSA-WITH-SHA384": "ECDSA-P384",
    "ECDSA-WITH-SHA512": "ECDSA-P521",
    "DSA-WITH-SHA1": "SHA-1", "DSA-WITH-SHA256": "DSA",
    "ED25519": "Ed25519", "ED448": "Ed448",
    "RSASSA-PSS-SHA256": "RSA-PSS",
    "SHA256WITHRSA": "RSA", "SHA1WITHRSA": "SHA-1", "MD5WITHRSA": "MD5",
    "RSASSA-PSS": "RSA-PSS", "RSAENCRYPTION": "RSA",
    "CURVE25519": "X25519", "EDWARDS25519": "Ed25519",
    "PRIME256V1": "ECDSA-P256", "SECP256R1": "ECDSA-P256",
    "SECP384R1": "ECDSA-P384", "SECP521R1": "ECDSA-P521",
    "NISTP256": "ECDSA-P256", "NISTP384": "ECDSA-P384", "NISTP521": "ECDSA-P521",
    "ML_KEM": "ML-KEM", "ML_DSA": "ML-DSA", "MLKEM": "ML-KEM", "MLDSA": "ML-DSA",
    "KYBER768": "Kyber", "KYBER512": "Kyber", "KYBER1024": "Kyber",
    "DILITHIUM3": "Dilithium", "DILITHIUM2": "Dilithium", "DILITHIUM5": "Dilithium",
    "SPHINCSPLUS": "SPHINCS+", "SPHINCS": "SPHINCS+",
    "DIFFIE-HELLMAN": "DH", "DHE": "DH", "ECDHE": "ECDH",
    "ARGON2ID": "Argon2", "ARGON2I": "Argon2", "ARGON2D": "Argon2",
    "RIPEMD160": "RIPEMD-160",
    "CHACHA20-POLY1305": "ChaCha20", "CHACHA20POLY1305": "ChaCha20",
}

_MODE_SUFFIXES = re.compile(
    r"[-/_](CBC|GCM|CTR|ECB|CFB|CFB8|OFB|XTS|KW|KWP|SIV|CCM|GCM-SIV|WRAP|POLY1305)$", re.I)
_PADDING_RE = re.compile(r"[-/_](OAEP|PSS|PKCS1|PKCS1V15|PKCS7|ISO9796|X931)$", re.I)
_HASH_SUFFIX = re.compile(r"[-/_](SHA1|SHA224|SHA256|SHA384|SHA512|SHA3|MD5)$", re.I)
_KEYSIZE_RE = re.compile(r"[-_ ]?(512|1024|1280|1536|2048|3072|4096|7680|8192|15360)$")

# Vendor/transport decorations that carry no algorithmic meaning:
#   aes256-gcm@openssh.com -> aes256-gcm
#   hmac-sha2-256-etm@openssh.com -> hmac-sha2-256
_VENDOR_SUFFIX = re.compile(r"(@[\w.\-]+|-etm|-draft\d*|-tls13)$", re.I)

# Key-exchange tokens, ordered so the weakest link is reported first. A cipher
# suite is only as strong as its key exchange under Shor, so ECDHE-RSA-AES256
# is an ECDH finding, not an AES one.
_KX_TOKENS = (
    ("ECDHE", "ECDH"), ("EECDH", "ECDH"), ("ECDH", "ECDH"),
    ("DHE", "DH"), ("EDH", "DH"), ("ADH", "DH"),
    ("SNTRUP761X25519", "sntrup761x25519"),
    ("MLKEM768X25519", "mlkem768x25519"),
    ("CURVE25519", "X25519"), ("X25519", "X25519"),
)

# Bulk ciphers as spelled in OpenSSL/SSH/IANA suite names. Matched with an
# optional separator so AES128, AES-128 and AES_128 all land on the same entry.
_BULK_PATTERNS = (
    (r"DES[-_]?CBC3", "3DES"),
    (r"3DES([-_]?EDE)?", "3DES"),
    (r"DES[-_]?EDE3?", "3DES"),
    (r"AES[-_]?256", "AES-256"),
    (r"AES[-_]?192", "AES-192"),
    (r"AES[-_]?128", "AES-128"),
    (r"CHACHA20", "ChaCha20"),
    (r"CAMELLIA[-_]?256", "Camellia-256"),
    (r"CAMELLIA[-_]?128", "Camellia-128"),
    (r"ARIA[-_]?256", "ARIA-256"),
    (r"ARIA[-_]?128", "ARIA-128"),
    (r"SEED", "SEED"),
    (r"IDEA", "IDEA"),
    (r"RC4([-_]?128)?", "RC4"),
    (r"RC2", "RC2"),
    (r"DES", "DES"),
)

# Suite-name markers that indicate we are looking at a cipher suite rather
# than a bare algorithm name.
_SUITE_MARKERS = re.compile(
    r"(^TLS[_-])|(ECDHE|EECDH|DHE|EDH|ADH)|"
    r"((AES|CAMELLIA|ARIA)[-_]?(128|192|256))|(DES-CBC3)|(RC4-)|(-SHA\d*$)|(-MD5$)", re.I)

# Modes that provide no integrity protection on their own.
UNAUTHENTICATED_MODES = {"CBC", "ECB", "CTR", "CFB", "OFB"}
AEAD_MODES = {"GCM", "CCM", "SIV", "POLY1305", "GCM-SIV", "OCB"}


def extract_mode(raw: str) -> str | None:
    """Return the block-cipher mode named in a raw algorithm string, if any."""
    m = _MODE_SUFFIXES.search(raw)
    if m:
        return m.group(1).upper()
    for token in re.split(r"[-/_ ]", raw.upper()):
        if token in UNAUTHENTICATED_MODES or token in AEAD_MODES:
            return token
    return None


def extract_padding(raw: str) -> str | None:
    m = _PADDING_RE.search(raw)
    return m.group(1).upper() if m else None


def canonical_algorithm(raw: str) -> tuple[str, dict | None]:
    """Normalise a raw algorithm string to a knowledge-base entry.

    Resolution order:
      1. exact match, then alias table
      2. vendor-suffix stripping (@openssh.com, -etm, -draft00)
      3. cipher-suite decomposition, reporting the WEAKEST link
      4. progressive suffix stripping (mode, padding, hash, key size)
      5. guarded substring match on a token boundary

    Returns (canonical_name, entry); entry is None when unrecognised. Callers
    must treat a None entry as genuinely unknown and never as safe.
    """
    if not raw:
        return "", None
    name = raw.strip().strip('"\'')
    if name in ALGORITHMS:
        return name, ALGORITHMS[name]

    upper = name.upper()
    if upper in ALIASES:
        key = ALIASES[upper]
        return key, ALGORITHMS.get(key)
    for candidate in (upper, name.replace("_", "-"), name.replace("_", "-").upper()):
        if candidate in ALGORITHMS:
            return candidate, ALGORITHMS[candidate]

    # Strip vendor/transport decoration, then retry exact + alias.
    stripped = _VENDOR_SUFFIX.sub("", name)
    while stripped != name:
        name, upper = stripped, stripped.upper()
        if name in ALGORITHMS:
            return name, ALGORITHMS[name]
        if upper in ALIASES:
            key = ALIASES[upper]
            return key, ALGORITHMS.get(key)
        stripped = _VENDOR_SUFFIX.sub("", name)

    # Cipher suites, in any spelling: TLS_ECDHE_RSA_WITH_..., ECDHE-RSA-AES128-SHA256,
    # DES-CBC3-SHA, aes256-gcm. Decomposed so the weakest component is reported.
    if _SUITE_MARKERS.search(upper):
        canon, entry = _resolve_cipher_suite(upper)
        if entry is not None:
            return canon, entry

    # Progressive suffix stripping. AES-256-GCM -> AES-256, RSA-2048-OAEP -> RSA.
    base = name
    for pattern in (_MODE_SUFFIXES, _PADDING_RE, _HASH_SUFFIX):
        for _ in range(3):
            m = pattern.search(base)
            if not m:
                break
            base = base[:m.start()]
            for candidate in (base, base.upper(), ALIASES.get(base.upper(), "")):
                if candidate in ALGORITHMS:
                    return candidate, ALGORITHMS[candidate]

    m = _KEYSIZE_RE.search(base)
    if m:
        stem = base[:m.start()]
        for candidate in (stem, stem.upper(), stem.replace("-", "").upper(),
                          ALIASES.get(stem.upper(), "")):
            if candidate in ALGORITHMS:
                return candidate, ALGORITHMS[candidate]

    # Guarded substring match. Requires a token boundary so that SHA does not
    # match inside SHAKE and AES does not match inside AESKEYWRAP.
    for key in sorted(ALGORITHMS, key=len, reverse=True):
        ku = key.upper()
        if len(ku) < 4:
            continue
        if re.search(rf"(?<![A-Z0-9]){re.escape(ku)}(?![A-Z0-9])", upper):
            return key, ALGORITHMS[key]
    return name, None


def _urgency_tier(entry: dict) -> int:
    """Rank an algorithm by how urgently it must be dealt with.

    0  already unusable: broken classically, or disallowed/prohibited by NIST
       today. These outrank quantum concerns because they are failures now.
    1  falls to Shor: asymmetric primitives, zero post-quantum strength.
    2  weakened by Grover: symmetric primitives below the 128-bit PQ floor.
    3  adequate: classical_ok or pq_safe.
    """
    status = str(entry.get("nist_status", "")).lower()
    if entry["impact"] == "broken_classically":
        return 0
    if any(flag in status for flag in ("disallowed", "prohibited", "deprecated", "broken")):
        return 0
    if entry["impact"] == "shor_broken":
        return 1
    if entry["impact"] == "grover":
        return 2
    return 3


def _resolve_cipher_suite(upper: str) -> tuple[str, dict | None]:
    """Decompose a cipher-suite name and return its weakest component.

    A suite is only as strong as its weakest part. Rather than guessing a fixed
    precedence, every component named in the suite is resolved and ranked by
    urgency tier, then by post-quantum strength. So:

        TLS_RSA_WITH_3DES_EDE_CBC_SHA   -> 3DES  (disallowed today, tier 0)
        ECDHE-RSA-AES256-GCM-SHA384     -> ECDH  (Shor, tier 1)
        AES128-SHA                      -> AES-128 (Grover, tier 2)

    The MAC hash in a suite name (the trailing -SHA / -SHA256) is deliberately
    not treated as a component: HMAC-SHA1 is not collision-broken, so reporting
    SHA-1 there would be a false positive.
    """
    normalised = upper.replace("_", "-")
    # (role_rank, algorithm_name, entry). Role rank breaks ties within an
    # urgency tier: when the key exchange and the authentication algorithm are
    # equally urgent, the key exchange is the one that matters, because that is
    # the harvest-now-decrypt-later vector.
    ROLE_KX, ROLE_BULK, ROLE_AUTH, ROLE_MAC = 0, 1, 2, 3
    candidates: list[tuple[int, str, dict]] = []

    def consider(role: int, algo_name: str | None):
        if not algo_name:
            return
        entry = ALGORITHMS.get(algo_name)
        if entry:
            candidates.append((role, algo_name, entry))

    # Anonymous / export / NULL suites have no confidentiality at all.
    if re.search(r"(?<![A-Z0-9])(NULL|EXPORT|EXP|ADH|AECDH|ANON)(?![A-Z0-9])", normalised):
        consider(ROLE_BULK, "RC4")  # stand-in for "no meaningful protection"

    # Key exchange.
    for token, algo in _KX_TOKENS:
        if re.search(rf"(?<![A-Z0-9]){token}(?![A-Z0-9])", normalised):
            consider(ROLE_KX, algo)
            break

    # RSA used for key transport or authentication.
    if re.search(r"(?<![A-Z0-9])RSA(?![A-Z0-9])", normalised):
        consider(ROLE_AUTH, "RSA")

    # Bulk cipher. First pattern wins; they are ordered most-specific first.
    for pattern, algo in _BULK_PATTERNS:
        if re.search(rf"(?<![A-Z0-9]){pattern}(?![A-Z0-9])", normalised):
            consider(ROLE_BULK, algo)
            break

    # An explicit MD5 MAC is a genuine finding, unlike SHA-1 in HMAC.
    if re.search(r"(?<![A-Z0-9])MD5(?![A-Z0-9])", normalised):
        consider(ROLE_MAC, "MD5")

    if not candidates:
        return upper, None

    # Worst component: lowest urgency tier first, then component role, then
    # least post-quantum strength.
    role, name, entry = min(candidates,
                            key=lambda c: (_urgency_tier(c[2]), c[0], c[2]["pq_bits"]))
    return name, entry


_ROLE_LABELS = {0: "key exchange", 1: "bulk cipher", 2: "authentication", 3: "mac"}


def decompose(raw: str) -> list[dict]:
    """Break a cipher-suite string into every crypto component it names.

    `canonical_algorithm` deliberately collapses a suite to its weakest link,
    because that is what a risk score should key off. But an analyst reading a
    config line wants the whole picture: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA is
    four decisions, three of which are findings. This returns all of them,
    ordered worst-first, so the UI can show the decomposition rather than
    appearing to silently drop RSA.

    Returns [] for strings that are not multi-component suites.
    """
    if not raw:
        return []
    upper = raw.strip().strip('"\'').upper()
    if not (upper.startswith(("TLS-", "TLS_", "SSL-", "SSL_"))
            or upper.count("-") >= 2 or upper.count("_") >= 2):
        return []

    normalised = upper.replace("_", "-")
    ROLE_KX, ROLE_BULK, ROLE_AUTH, ROLE_MAC = 0, 1, 2, 3
    found: list[tuple[int, str, dict]] = []
    seen: set[str] = set()

    def add(role: int, algo_name: str | None):
        if not algo_name or algo_name in seen:
            return
        entry = ALGORITHMS.get(algo_name)
        if entry:
            seen.add(algo_name)
            found.append((role, algo_name, entry))

    for token, algo in _KX_TOKENS:
        if re.search(rf"(?<![A-Z0-9]){token}(?![A-Z0-9])", normalised):
            add(ROLE_KX, algo)
            break
    if re.search(r"(?<![A-Z0-9])RSA(?![A-Z0-9])", normalised):
        add(ROLE_AUTH, "RSA")
    for pattern, algo in _BULK_PATTERNS:
        if re.search(rf"(?<![A-Z0-9]){pattern}(?![A-Z0-9])", normalised):
            add(ROLE_BULK, algo)
            break
    # The trailing hash in a suite is the HMAC/PRF hash. HMAC-SHA1 is not
    # collision-broken, so it is reported as the MAC role with that caveat
    # rather than as a SHA-1 signature finding.
    for token, algo in (("SHA384", "SHA-384"), ("SHA256", "SHA-256"),
                        ("SHA1", "SHA-1"), ("SHA", "SHA-1"), ("MD5", "MD5")):
        if re.search(rf"(?<![A-Z0-9]){token}(?![A-Z0-9])", normalised):
            add(ROLE_MAC, algo)
            break

    if len(found) < 2:
        return []

    # `weakest` must agree with what canonical_algorithm actually scored,
    # otherwise the UI would flag a component the risk model never used. The MAC
    # hash is deliberately not a scoring candidate (HMAC-SHA1 is not forgeable),
    # so it can outrank the real answer on urgency tier alone.
    scored_name, _ = canonical_algorithm(raw)
    # Order: scored component first, then remaining by urgency, role, pq strength.
    found.sort(key=lambda c: (c[1] != scored_name, _urgency_tier(c[2]), c[0], c[2]["pq_bits"]))
    out = []
    for role, name, entry in found:
        note = entry.get("note")
        if role == ROLE_MAC and name in ("SHA-1", "MD5"):
            note = (f"Used as the HMAC/PRF hash here. HMAC with {name} is not "
                    "collision-broken, so this is a hygiene finding, not a forgery risk.")
        out.append({
            "role": _ROLE_LABELS[role],
            "name": name,
            "impact": entry["impact"],
            "primitive": entry.get("primitive"),
            "classical_bits": entry.get("classical_bits"),
            "pq_bits": entry.get("pq_bits"),
            "nist_status": entry.get("nist_status"),
            "note": note,
            "weakest": name == scored_name,
        })
    return out


def impact_of(raw: str) -> str:
    _, entry = canonical_algorithm(raw)
    return (entry or {}).get("impact", "unknown")


def stats() -> dict:
    impacts: dict[str, int] = {}
    primitives: dict[str, int] = {}
    for entry in ALGORITHMS.values():
        impacts[entry["impact"]] = impacts.get(entry["impact"], 0) + 1
        p = entry.get("primitive", "unknown")
        primitives[p] = primitives.get(p, 0) + 1
    return {"algorithms": len(ALGORITHMS), "aliases": len(ALIASES),
            "by_impact": impacts, "by_primitive": primitives}
