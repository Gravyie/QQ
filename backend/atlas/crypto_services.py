"""Crypto libraries, cloud services, HSM hardware knowledge."""
from __future__ import annotations

# name-keyed registry; mlkem=True means a version exists with PQC support
LIBRARIES: dict[str, dict] = {
    "openssl": {"pqc": True, "pqc_note": "X25519MLKEM768 hybrid in 3.5+; ML-KEM stable in 3.6",
                "category": "tls-crypto"},
    "boringssl": {"pqc": True, "pqc_note": "X25519MLKEM768 deployed for Chrome TLS", "category": "tls-crypto"},
    "liboqs": {"pqc": True, "pqc_note": "Dedicated PQC library; ML-KEM/ML-DSA/SLH-DSA", "category": "pqc"},
    "liboqs-python": {"pqc": True, "pqc_note": "Python bindings to liboqs", "category": "pqc"},
    "oqs-provider": {"pqc": True, "pqc_note": "OpenSSL 3 provider for PQC algorithms", "category": "pqc"},
    "cryptography": {"pqc": True, "pqc_note": "PyCA; AWS-LC variant ships ML-KEM hybrid TLS groups", "category": "tls-crypto"},
    "pyopenssl": {"pqc": False, "pqc_note": "Wraps OpenSSL; PQC only if linked OpenSSL supports it", "category": "tls-crypto"},
    "rustls": {"pqc": True, "pqc_note": "ML-KEM hybrid groups since 0.23; ML-DSA in 1.0+", "category": "tls-crypto"},
    "wolfssl": {"pqc": True, "pqc_note": "ML-KEM/ML-DSA experimental 5.7+, stable 6.0", "category": "tls-crypto"},
    "mbedtls": {"pqc": True, "pqc_note": "ML-KEM experimental in 3.6.x via PSA drivers", "category": "tls-crypto"},
    "gnutls": {"pqc": True, "pqc_note": "ML-DSA landed in 3.8.9 (2025)", "category": "tls-crypto"},
    "botan": {"pqc": True, "pqc_note": "ML-KEM/ML-DSA/SLH-DSA/Falcon in 3.6+", "category": "tls-crypto"},
    "libressl": {"pqc": False, "pqc_note": "No PQC support yet", "category": "tls-crypto"},
    "libgcrypt": {"pqc": False, "pqc_note": "No PQC support yet", "category": "tls-crypto"},
    "libsodium": {"pqc": False, "pqc_note": "No PQC support yet", "category": "tls-crypto"},
    "nss": {"pqc": False, "pqc_note": "No PQC support yet (as of 3.107)", "category": "tls-crypto"},
    "bouncycastle": {"pqc": True, "pqc_note": "Java/C#: ML-KEM/ML-DSA/SLH-DSA since 1.80 (2025)",
                     "category": "multi", "min_pqc_version": "1.80"},
    "bcprov-jdk18on": {"pqc": True, "pqc_note": "BouncyCastle provider; PQC since 1.80", "category": "multi",
                       "min_pqc_version": "1.80"},
    "bcpkix-jdk18on": {"pqc": True, "pqc_note": "BouncyCastle PKIX; PQC since 1.80", "category": "multi",
                       "min_pqc_version": "1.80"},
    "tink": {"pqc": False, "pqc_note": "No PQC key types yet (as of 1.16)", "category": "multi"},
    "tink-java": {"pqc": False, "pqc_note": "No PQC key types yet", "category": "multi"},
    "tink-py": {"pqc": False, "pqc_note": "No PQC key types yet", "category": "multi"},
    "jose4j": {"pqc": False, "pqc_note": "JOSE has no PQC algorithms standardized yet", "category": "jose"},
    "python-jose": {"pqc": False, "pqc_note": "JOSE has no PQC algorithms standardized yet", "category": "jose"},
    "pyjwt": {"pqc": False, "pqc_note": "JWT algorithms are classical (RS/ES/Ed)", "category": "jose"},
    "jsonwebtoken": {"pqc": False, "pqc_note": "JWT algorithms are classical", "category": "jose"},
    "node-jose": {"pqc": False, "pqc_note": "JOSE classical only", "category": "jose"},
    "jose": {"pqc": False, "pqc_note": "JOSE classical only (Go)", "category": "jose"},
    "keycloak": {"pqc": False, "pqc_note": "Classical SSO signing (RSA/ECDSA) today", "category": "iam"},
    "aws-kms": {"pqc": False, "pqc_note": "KMS API TLS supports ML-KEM hybrid; stored keys classical",
                "category": "cloud-kms"},
    "google-cloud-kms": {"pqc": False, "pqc_note": "Hybrid TLS to API; stored keys classical", "category": "cloud-kms"},
    "azure-keyvault": {"pqc": False, "pqc_note": "Hybrid TLS; stored keys classical", "category": "cloud-kms"},
    "hashicorp-vault": {"pqc": False, "pqc_note": "Transit engine classical; PQC on roadmap", "category": "cloud-kms"},
    "vault": {"pqc": False, "pqc_note": "Transit engine classical; PQC on roadmap", "category": "cloud-kms"},
    "aws-encryption-sdk": {"pqc": False, "pqc_note": "Envelope encryption uses KMS (classical keys)", "category": "cloud-kms"},
    "google-tink": {"pqc": False, "pqc_note": "No PQC key types yet", "category": "multi"},
}

# HSM / hardware modules
HARDWARE: dict[str, dict] = {
    "pkcs11": {"kind": "interface", "note": "PKCS#11 interface detected: HSM integration point"},
    "hsm": {"kind": "device", "note": "Generic HSM reference"},
    "luna-hsm": {"kind": "device", "vendor": "Thales", "note": "Luna HSM; PQC firmware 7.8+ partial"},
    "nshield": {"kind": "device", "vendor": "Entrust", "note": "nShield; PQC roadmap"},
    "cloudhsm": {"kind": "device", "vendor": "AWS", "note": "AWS CloudHSM; classical only today"},
    "yubihsm": {"kind": "device", "vendor": "Yubico", "note": "YubiHSM 2; classical only"},
    "softhsm": {"kind": "device", "vendor": "Open", "note": "SoftHSM (software): test-only, not production"},
    "tpm": {"kind": "device", "note": "TPM 2.0; classical algorithms only (RSA/ECC/SHA)"},
    "nitrokey": {"kind": "device", "vendor": "Nitrokey", "note": "Nitrokey HSM; classical"},
    "utimaco": {"kind": "device", "vendor": "Utimaco", "note": "CryptoServer; PQC firmware available"},
}

# Cloud service SDK markers (source-level detection)
CLOUD_SERVICES: dict[str, dict] = {
    "boto3": {"service": "AWS KMS / AWS services", "crypto_role": "kms"},
    "aioboto3": {"service": "AWS KMS / AWS services", "crypto_role": "kms"},
    "aws-sdk": {"service": "AWS services", "crypto_role": "kms"},
    "@aws-sdk/client-kms": {"service": "AWS KMS", "crypto_role": "kms"},
    "google-cloud-kms": {"service": "Google Cloud KMS", "crypto_role": "kms"},
    "azure-identity": {"service": "Azure (Key Vault reachable)", "crypto_role": "kms"},
    "azure-keyvault-keys": {"service": "Azure Key Vault Keys", "crypto_role": "kms"},
    "azure-security-keyvault-keys": {"service": "Azure Key Vault Keys", "crypto_role": "kms"},
    "hvac": {"service": "HashiCorp Vault", "crypto_role": "kms"},
    "vault": {"service": "HashiCorp Vault", "crypto_role": "kms"},
    "kubernetes": {"service": "Kubernetes secrets", "crypto_role": "secrets"},
    "javax.crypto": {"service": "JCE (Java)", "crypto_role": "local"},
    "java.security": {"service": "JCA (Java)", "crypto_role": "local"},
}

# TLS protocol versions
PROTOCOLS: dict[str, dict] = {
    "TLS": {"versions": {"1.0": "unsafe", "1.1": "unsafe", "1.2": "acceptable", "1.3": "good"}},
    "SSL": {"versions": {"2.0": "unsafe", "3.0": "unsafe"}},
    "SSH": {"versions": {"1": "unsafe", "2": "acceptable"}},
    "IPsec": {"versions": {"ikev1": "unsafe", "ikev2": "acceptable"}},
    "S/MIME": {"versions": {"3.0": "acceptable"}},
    "PGP": {"versions": {"2": "unsafe", "openpgp": "acceptable"}},
}


def lookup_library(name: str) -> tuple[str, dict | None]:
    n = name.lower().strip()
    if n in LIBRARIES:
        return n, LIBRARIES[n]
    # normalized containment match
    for key in LIBRARIES:
        if key in n or n in key:
            return key, LIBRARIES[key]
    return n, None
