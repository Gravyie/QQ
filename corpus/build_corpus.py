#!/usr/bin/env python3
"""Build the scan corpus.

Two kinds of target are produced:

1. `corpus/real/` — clones of genuine open-source repositories. Nothing is
   authored here; these exist so the scanner is proven against code it has
   never seen. Cloned shallow to keep the tree small.

2. `corpus/estate/` — a synthetic enterprise estate ("Meridian Financial"),
   authored to contain a realistic spread of cryptographic artefacts: source
   using weak and strong primitives, real X.509 certificates (generated with
   `cryptography`, including a genuinely expired one), real private keys,
   server configs pinning obsolete TLS, dependency manifests, and a
   docker-save-shaped tarball with layers.

Everything in `estate/` is real parseable material — real DER certificates,
real PEM keys — not placeholder strings. The scanner has no special knowledge
of this directory.
"""
from __future__ import annotations

import argparse
import datetime as dt
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent
ESTATE = ROOT / "estate"
REAL = ROOT / "real"

# Shallow clones of genuine crypto-heavy projects. Kept small on purpose:
# the point is unseen third-party code, not volume.
REPOS = [
    ("https://github.com/pyca/cryptography.git", "pyca-cryptography"),
    ("https://github.com/paramiko/paramiko.git", "paramiko"),
    ("https://github.com/jpadilla/pyjwt.git", "pyjwt"),
]


# --------------------------------------------------------------------------
# certificate + key generation
# --------------------------------------------------------------------------
def _name(cn: str, org: str = "Meridian Financial Services") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Maharashtra"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def make_cert(cn: str, key, *, issuer_key=None, issuer_name=None,
              days_valid: int = 365, days_ago_issued: int = 0,
              hash_alg=None, ca: bool = False, sans: list[str] | None = None):
    """Build a real X.509 certificate. days_ago_issued lets us mint an expired one."""
    now = dt.datetime.now(dt.timezone.utc)
    not_before = now - dt.timedelta(days=days_ago_issued)
    not_after = not_before + dt.timedelta(days=days_valid)
    subject = _name(cn)
    issuer = issuer_name or subject
    signing_key = issuer_key or key
    pub = key.public_key()

    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(issuer)
               .public_key(pub)
               .serial_number(x509.random_serial_number())
               .not_valid_before(not_before)
               .not_valid_after(not_after)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)

    if isinstance(signing_key, ed25519.Ed25519PrivateKey):
        return builder.sign(signing_key, None)
    return builder.sign(signing_key, hash_alg or hashes.SHA256())


def write_pem(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def priv_pem(key, password: bytes | None = None) -> bytes:
    enc = (serialization.BestAvailableEncryption(password) if password
           else serialization.NoEncryption())
    return key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8, enc)


def _mint_sha1_expired_cert(ca_key, ca_cert, out_path: Path) -> bool:
    """Mint a SHA-1-signed, already-expired certificate via system OpenSSL.

    `cryptography` blocks SHA-1 signatures outright, but a real enterprise
    estate contains them, and the scanner needs to prove it parses one. The
    OpenSSL `ca` command still permits `-md sha1` plus explicit past
    -startdate/-enddate. Returns False if openssl is missing or fails.
    """
    if shutil.which("openssl") is None:
        return False

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "newcerts").mkdir()
        (tmp / "index.txt").write_text("")
        (tmp / "serial").write_text("1000\n")
        (tmp / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        (tmp / "ca.key").write_bytes(
            ca_key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.TraditionalOpenSSL,
                                 serialization.NoEncryption()))
        (tmp / "ca.cnf").write_text(
            "[ ca ]\ndefault_ca = CA_default\n\n"
            "[ CA_default ]\n"
            f"dir = {tmp}\n"
            f"database = {tmp}/index.txt\n"
            f"new_certs_dir = {tmp}/newcerts\n"
            f"serial = {tmp}/serial\n"
            "default_md = sha1\npolicy = policy_any\n"
            "email_in_dn = no\nunique_subject = no\n\n"
            "[ policy_any ]\ncommonName = supplied\n")

        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        (tmp / "leaf.key").write_bytes(priv_pem(leaf_key))

        csr = subprocess.run(
            ["openssl", "req", "-new", "-key", str(tmp / "leaf.key"),
             "-out", str(tmp / "leaf.csr"), "-subj",
             "/CN=legacy-clearing.partner.example"],
            capture_output=True)
        if csr.returncode != 0:
            return False

        signed = subprocess.run(
            ["openssl", "ca", "-batch", "-config", str(tmp / "ca.cnf"),
             "-cert", str(tmp / "ca.pem"), "-keyfile", str(tmp / "ca.key"),
             "-in", str(tmp / "leaf.csr"), "-out", str(tmp / "leaf.pem"),
             "-md", "sha1",
             "-startdate", "20220101000000Z", "-enddate", "20240101000000Z"],
            capture_output=True)
        if signed.returncode != 0 or not (tmp / "leaf.pem").exists():
            return False

        # `openssl ca` prepends a text dump; keep only the PEM block.
        text = (tmp / "leaf.pem").read_text()
        start = text.find("-----BEGIN CERTIFICATE-----")
        if start < 0:
            return False
        out_path.write_text(text[start:])
        return True


def build_pki():
    """Generate the estate PKI. Deliberately mixed quality."""
    pki = ESTATE / "infra" / "pki"

    # Root CA: RSA-4096, SHA-256. Long-lived — worst HNDL profile.
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ca_cert = make_cert("Meridian Root CA", ca_key, days_valid=3650, ca=True)
    write_pem(pki / "ca" / "root-ca.pem", ca_cert.public_bytes(serialization.Encoding.PEM))
    write_pem(pki / "ca" / "root-ca.key", priv_pem(ca_key))

    # Public payments gateway: RSA-2048. External-facing → high HNDL exposure.
    gw_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    gw = make_cert("payments-gateway.meridian.example", gw_key,
                   issuer_key=ca_key, issuer_name=ca_cert.subject,
                   days_valid=397, sans=["payments-gateway.meridian.example",
                                         "api.meridian.example"])
    write_pem(pki / "public" / "payments-gateway.pem",
              gw.public_bytes(serialization.Encoding.PEM) +
              ca_cert.public_bytes(serialization.Encoding.PEM))
    write_pem(pki / "public" / "payments-gateway.key", priv_pem(gw_key))

    # Internal service mesh: ECDSA P-256, short-lived.
    mesh_key = ec.generate_private_key(ec.SECP256R1())
    mesh = make_cert("mesh.internal.meridian", mesh_key,
                     issuer_key=ca_key, issuer_name=ca_cert.subject, days_valid=90)
    write_pem(pki / "internal" / "service-mesh.pem",
              mesh.public_bytes(serialization.Encoding.PEM))
    write_pem(pki / "internal" / "service-mesh.key", priv_pem(mesh_key))

    # Legacy partner link: SHA-1 signature, expired two years ago.
    # `cryptography` refuses to sign with SHA-1 (correctly), so this one cert
    # is minted through the system OpenSSL `ca` command, which still allows
    # -md sha1 and explicit past validity dates. If OpenSSL is unavailable the
    # corpus degrades to a SHA-256 expired cert and says so.
    legacy_path = pki / "legacy" / "clearing-partner.crt"
    legacy_path.parent.mkdir(parents=True, exist_ok=True)
    if not _mint_sha1_expired_cert(ca_key, ca_cert, legacy_path):
        legacy_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        legacy = make_cert("legacy-clearing.partner.example", legacy_key,
                           issuer_key=ca_key, issuer_name=ca_cert.subject,
                           days_valid=730, days_ago_issued=1460)
        write_pem(legacy_path, legacy.public_bytes(serialization.Encoding.PEM))
        print("  ! openssl unavailable: legacy cert minted with SHA-256, not SHA-1")

    # DER-encoded cert, to prove non-PEM parsing.
    der_key = ec.generate_private_key(ec.SECP384R1())
    der_cert = make_cert("edge-cdn.meridian.example", der_key,
                         issuer_key=ca_key, issuer_name=ca_cert.subject, days_valid=180)
    write_pem(pki / "edge" / "edge-cdn.der",
              der_cert.public_bytes(serialization.Encoding.DER))

    # Code-signing identity: DSA. Withdrawn by FIPS 186-5.
    dsa_key = dsa.generate_private_key(key_size=2048)
    dsa_cert = make_cert("build-signing.meridian", dsa_key,
                         issuer_key=ca_key, issuer_name=ca_cert.subject, days_valid=1095)
    write_pem(pki / "signing" / "build-signing.pem",
              dsa_cert.public_bytes(serialization.Encoding.PEM))
    write_pem(pki / "signing" / "build-signing.key", priv_pem(dsa_key))

    # Ed25519 for internal admin — Shor-broken but modern.
    ed_key = ed25519.Ed25519PrivateKey.generate()
    ed_cert = make_cert("admin-portal.internal.meridian", ed_key,
                        issuer_key=ca_key, issuer_name=ca_cert.subject, days_valid=365)
    write_pem(pki / "internal" / "admin-portal.pem",
              ed_cert.public_bytes(serialization.Encoding.PEM))

    # Unencrypted RSA key checked into a repo path — the classic finding.
    leaked = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    write_pem(ESTATE / "payments-service" / "config" / "secrets" / "jwt-signing.key",
              leaked.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.TraditionalOpenSSL,
                                   serialization.NoEncryption()))

    # Passphrase-protected key, for contrast.
    prot = ec.generate_private_key(ec.SECP256R1())
    write_pem(ESTATE / "infra" / "pki" / "internal" / "vault-unseal.key",
              priv_pem(prot, password=b"corpus-demo-not-a-real-secret"))

    return {"root_ca": str(pki / "ca" / "root-ca.pem")}


# --------------------------------------------------------------------------
# source trees
# --------------------------------------------------------------------------
PAYMENTS_TOKENS = '''"""Card tokenisation for the Meridian payments gateway.

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
    padded = pan + b"\\x00" * (16 - len(pan) % 16)
    return enc.update(padded) + enc.finalize()


def derive_terminal_key(shared_secret: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return kdf.derive(shared_secret)


def terminal_receipt_mac(payload: bytes, key: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def legacy_terminal_id(serial: str) -> str:
    """v1 terminals identify themselves by an MD5 of their serial."""
    return hashlib.md5(serial.encode()).hexdigest()
'''

PAYMENTS_SETTLEMENT = '''"""Nightly settlement file signing and partner key exchange."""
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
'''

TREASURY_ARCHIVE = '''"""Long-term treasury archive.

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
'''

AUTH_SESSION_JAVA = '''package com.meridian.auth;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;

/** Session token issuing for the customer web channel. */
public final class SessionTokenService {

    /** RSA-2048 keypair backing the JWT RS256 signature. */
    public static java.security.KeyPair issueSigningKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static byte[] signToken(byte[] claims, java.security.PrivateKey key) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(claims);
        return signature.sign();
    }

    /** Legacy SSO partner still validates SHA1withRSA assertions. */
    public static byte[] signLegacyAssertion(byte[] assertion, java.security.PrivateKey key)
            throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(key);
        signature.update(assertion);
        return signature.sign();
    }

    public static SecretKey sessionKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        return generator.generateKey();
    }

    public static byte[] wrapSessionKey(SecretKey sessionKey, java.security.PublicKey pub)
            throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.WRAP_MODE, pub);
        return cipher.wrap(sessionKey);
    }

    /** Cookie fingerprint. MD5 retained for cache-key compatibility. */
    public static String cookieFingerprint(byte[] cookie) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return java.util.HexFormat.of().formatHex(digest.digest(cookie));
    }
}
'''

AUTH_LEGACY_JAVA = '''package com.meridian.auth.legacy;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Branch-terminal channel from the 2004 core banking integration. */
public final class BranchTerminalCipher {

    /** Triple DES. Disallowed by NIST SP 800-131A Rev.2 since 2023. */
    public static byte[] encryptBranchMessage(byte[] message, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"));
        return cipher.doFinal(message);
    }

    /** Single DES. Present only in the ATM reconciliation path. */
    public static byte[] encryptReconciliation(byte[] message, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
        return cipher.doFinal(message);
    }
}
'''

EDGE_API_TS = '''/**
 * Public API edge: request signing and webhook verification.
 * Internet-facing, so every primitive here is on the harvest path.
 */
import { createHash, createSign, generateKeyPairSync, createCipheriv } from "node:crypto";

export function issueWebhookKeyPair() {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

export function issueEdgeIdentity() {
  return generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

export function signWebhook(body: string, privateKey: string): string {
  const signer = createSign("RSA-SHA256");
  signer.update(body);
  return signer.sign(privateKey, "base64");
}

/** Cache key for the edge CDN. Not a security boundary. */
export function cacheKey(url: string): string {
  return createHash("md5").update(url).digest("hex");
}

/** Partner v1 payload encryption. Scheduled for removal. */
export function encryptPartnerV1(payload: Buffer, key: Buffer, iv: Buffer): Buffer {
  const cipher = createCipheriv("aes-128-cbc", key, iv);
  return Buffer.concat([cipher.update(payload), cipher.final()]);
}
'''

MESH_GO = '''// Service mesh identity and mTLS bootstrap for internal traffic.
package mesh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
)

// IssueWorkloadIdentity mints the short-lived ECDSA P-256 workload cert key.
func IssueWorkloadIdentity() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// IssueMeshRoot mints the mesh intermediate. RSA for HSM compatibility.
func IssueMeshRoot() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

// IssueNodeIdentity is the newer Ed25519 node identity.
func IssueNodeIdentity() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// legacyThumbprint matches the fingerprint format the old control plane expects.
func legacyThumbprint(der []byte) [20]byte {
	return sha1.Sum(der)
}

// MeshTLSConfig pins TLS 1.2 because the 2019 sidecar fleet cannot do 1.3.
func MeshTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}
}
'''

HSM_C = '''/* PKCS#11 bridge to the branch HSM estate (Thales Luna).
 * Card key ceremonies run through here.
 */
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/sha.h>

#include "pkcs11.h"

static CK_FUNCTION_LIST_PTR hsm = NULL;

int hsm_open_session(CK_SLOT_ID slot, CK_SESSION_HANDLE *session) {
    return hsm->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL, NULL, session);
}

/* Zone master key wrapping still uses 3DES on the older Luna firmware. */
int wrap_zone_master_key(unsigned char *out, const unsigned char *in, size_t len,
                         const unsigned char *kek) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0;
    EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, kek, NULL);
    EVP_EncryptUpdate(ctx, out, &outl, in, (int)len);
    EVP_CIPHER_CTX_free(ctx);
    return outl;
}

/* Newer ceremonies use AES-256-GCM. */
int wrap_working_key(unsigned char *out, const unsigned char *in, size_t len,
                     const unsigned char *kek, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, kek, iv);
    EVP_EncryptUpdate(ctx, out, &outl, in, (int)len);
    EVP_CIPHER_CTX_free(ctx);
    return outl;
}

int hsm_generate_signing_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *pub,
                             CK_OBJECT_HANDLE *priv) {
    CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
    return hsm->C_GenerateKeyPair(session, &mech, NULL, 0, NULL, 0, pub, priv);
}
'''

KMS_PY = '''"""Cloud KMS envelope encryption for the document store."""
import base64

import boto3
from google.cloud import kms
from azure.keyvault.keys.crypto import CryptographyClient

_kms = boto3.client("kms")


def generate_data_key(key_id: str) -> tuple[bytes, bytes]:
    """AWS KMS generates the AES-256 data key; the CMK itself is RSA-4096."""
    response = _kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
    return response["Plaintext"], response["CiphertextBlob"]


def gcp_asymmetric_sign(key_name: str, digest: bytes) -> bytes:
    client = kms.KeyManagementServiceClient()
    return client.asymmetric_sign(
        request={"name": key_name, "digest": {"sha256": digest}}
    ).signature


def azure_unwrap(client: CryptographyClient, wrapped: bytes) -> bytes:
    return client.unwrap_key("RSA-OAEP", wrapped).key


def vault_transit_encrypt(client, mount: str, plaintext: bytes) -> str:
    """HashiCorp Vault transit engine. Backing key is AES-256-GCM."""
    result = client.secrets.transit.encrypt_data(
        mount_point=mount, name="documents",
        plaintext=base64.b64encode(plaintext).decode())
    return result["data"]["ciphertext"]
'''

PQC_PILOT_PY = '''"""PQC pilot for the interbank channel.

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
'''

CORE_BANKING_CS = '''using System;
using System.Security.Cryptography;

namespace Meridian.CoreBanking
{
    /// <summary>Account number protection in the .NET core banking adapter.</summary>
    public static class AccountProtection
    {
        public static RSA CreateAccountSigningKey() => RSA.Create(2048);

        public static ECDsa CreateStatementSigningKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public static byte[] EncryptAccountNumber(byte[] plaintext, byte[] key, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            using var encryptor = aes.CreateEncryptor(key, iv);
            return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }

        // Statement checksum from the mainframe era.
        public static byte[] StatementChecksum(byte[] statement)
        {
            using var sha1 = SHA1.Create();
            return sha1.ComputeHash(statement);
        }
    }
}
'''

NGINX_CONF = '''# Meridian public edge — payments gateway termination
user  nginx;
worker_processes  auto;

http {
    ssl_session_cache   shared:SSL:20m;
    ssl_session_timeout 10m;

    server {
        listen 443 ssl http2;
        server_name payments-gateway.meridian.example;

        ssl_certificate     /etc/meridian/pki/public/payments-gateway.pem;
        ssl_certificate_key /etc/meridian/pki/public/payments-gateway.key;

        # Partner v1 terminals cannot negotiate TLS 1.2.
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA:AES128-SHA:DES-CBC3-SHA;
        ssl_prefer_server_ciphers on;

        location /v1/authorize {
            proxy_pass http://payments-upstream;
        }
    }

    server {
        listen 443 ssl;
        server_name admin-portal.internal.meridian;

        ssl_certificate     /etc/meridian/pki/internal/admin-portal.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    }
}
'''

SSHD_CONFIG = '''# Meridian bastion — jump host into the payments VPC
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha1
Ciphers aes256-gcm@openssh.com,aes128-ctr,3des-cbc
MACs hmac-sha2-256,hmac-sha1

PermitRootLogin no
PasswordAuthentication no
'''

OPENSSL_CNF = '''[ req ]
default_bits        = 2048
default_md          = sha256
distinguished_name  = req_distinguished_name

[ req_distinguished_name ]
countryName         = IN
organizationName    = Meridian Financial Services

[ legacy_partner ]
default_bits        = 1024
default_md          = sha1

[ system_default_sect ]
MinProtocol = TLSv1
CipherString = DEFAULT@SECLEVEL=1
'''

APACHE_CONF = '''# Legacy statements portal, pending decommission
<VirtualHost *:443>
    ServerName statements.meridian.example
    SSLEngine on
    SSLProtocol -all +TLSv1 +TLSv1.1 +TLSv1.2
    SSLCipherSuite ECDHE-RSA-AES256-SHA384:AES256-SHA256:DES-CBC3-SHA:RC4-SHA
    SSLCertificateFile /etc/meridian/pki/legacy/clearing-partner.crt
</VirtualHost>
'''

REQUIREMENTS = '''# payments-service runtime
cryptography==41.0.7
pyjwt==2.8.0
boto3==1.34.14
hvac==2.1.0
paramiko==3.4.0
requests==2.31.0
pyopenssl==23.3.0
bcrypt==4.1.2
'''

PQC_REQUIREMENTS = '''# interbank PQC pilot
liboqs-python==0.10.0
cryptography==44.0.0
'''

PACKAGE_JSON = json.dumps({
    "name": "meridian-edge-api",
    "version": "3.4.1",
    "private": True,
    "dependencies": {
        "jsonwebtoken": "9.0.2",
        "node-forge": "1.3.1",
        "jose": "5.2.0",
        "express": "4.18.2",
        "bcrypt": "5.1.1",
    },
    "devDependencies": {"typescript": "5.3.3"},
}, indent=2)

POM_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.meridian</groupId>
  <artifactId>auth-service</artifactId>
  <version>7.2.0</version>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.72</version>
    </dependency>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcpkix-jdk18on</artifactId>
      <version>1.72</version>
    </dependency>
    <dependency>
      <groupId>org.bitbucket.b_c</groupId>
      <artifactId>jose4j</artifactId>
      <version>0.9.4</version>
    </dependency>
  </dependencies>
</project>
'''

GO_MOD = '''module github.com/meridian/service-mesh

go 1.22

require (
	github.com/hashicorp/vault/api v1.11.0
	golang.org/x/crypto v0.18.0
	google.golang.org/grpc v1.60.1
)
'''

TERRAFORM = '''# Payments VPC key management
resource "aws_kms_key" "pan_master" {
  description              = "PAN tokenisation master key"
  customer_master_key_spec = "RSA_4096"
  key_usage                = "ENCRYPT_DECRYPT"
  enable_key_rotation      = false
}

resource "aws_kms_key" "settlement_signing" {
  description              = "Settlement batch signing"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
}

resource "aws_cloudhsm_v2_cluster" "branch_hsm" {
  hsm_type   = "hsm1.medium"
  subnet_ids = var.private_subnets
}

resource "aws_lb_listener" "payments" {
  protocol   = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
}
'''

SOURCES: dict[str, str] = {
    "payments-service/src/tokenisation.py": PAYMENTS_TOKENS,
    "payments-service/src/settlement.py": PAYMENTS_SETTLEMENT,
    "payments-service/requirements.txt": REQUIREMENTS,
    "payments-service/config/nginx.conf": NGINX_CONF,
    "payments-service/infra/kms.tf": TERRAFORM,
    "treasury-archive/src/archive.py": TREASURY_ARCHIVE,
    "auth-service/src/main/java/com/meridian/auth/SessionTokenService.java": AUTH_SESSION_JAVA,
    "auth-service/src/main/java/com/meridian/auth/legacy/BranchTerminalCipher.java": AUTH_LEGACY_JAVA,
    "auth-service/pom.xml": POM_XML,
    "edge-api/src/signing.ts": EDGE_API_TS,
    "edge-api/package.json": PACKAGE_JSON,
    "service-mesh/mesh.go": MESH_GO,
    "service-mesh/go.mod": GO_MOD,
    "branch-hsm-bridge/src/hsm_bridge.c": HSM_C,
    "document-store/src/kms_envelope.py": KMS_PY,
    "core-banking-adapter/AccountProtection.cs": CORE_BANKING_CS,
    "interbank-pqc-pilot/src/pilot.py": PQC_PILOT_PY,
    "interbank-pqc-pilot/requirements.txt": PQC_REQUIREMENTS,
    "infra/bastion/sshd_config": SSHD_CONFIG,
    "infra/openssl/openssl.cnf": OPENSSL_CNF,
    "infra/statements/apache-ssl.conf": APACHE_CONF,
}


def build_sources():
    for rel, content in SOURCES.items():
        path = ESTATE / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


# --------------------------------------------------------------------------
# container image
# --------------------------------------------------------------------------
def build_container_image():
    """Produce a docker-save-shaped tarball with per-layer content.

    Layer members mirror what `docker save` emits: a manifest, per-layer tars.
    Our ContainerScanner walks members directly, so a flat set of realistic
    paths inside layer directories is what matters.
    """
    out = ESTATE / "images" / "payments-gateway-3.4.1.tar"
    out.parent.mkdir(parents=True, exist_ok=True)

    # Embedded ELF-shaped blob carrying real version strings, so the binary
    # scanner has something genuine to find.
    openssl_blob = (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56 +
                    b"OpenSSL 1.1.1f  31 Mar 2020\x00" +
                    b"SSLv3 part of OpenSSL 1.1.1f\x00" +
                    b"TLSv1.2\x00TLSv1\x00" + b"\x00" * 512)
    libgcrypt_blob = (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56 +
                      b"libgcrypt 1.8.5\x00" + b"\x00" * 256)

    layers = {
        "d1f0a9c3e7b2/layer.tar": {
            "usr/lib/x86_64-linux-gnu/libssl.so.1.1": openssl_blob,
            "usr/lib/x86_64-linux-gnu/libgcrypt.so.20": libgcrypt_blob,
            "etc/ssl/openssl.cnf": OPENSSL_CNF.encode(),
        },
        "8c4b7e1d9f60/layer.tar": {
            "etc/nginx/nginx.conf": NGINX_CONF.encode(),
            "etc/ssh/sshd_config": SSHD_CONFIG.encode(),
        },
        "3a9e5c2b8d14/layer.tar": {
            "app/src/tokenisation.py": PAYMENTS_TOKENS.encode(),
            "app/src/settlement.py": PAYMENTS_SETTLEMENT.encode(),
            "app/requirements.txt": REQUIREMENTS.encode(),
            "app/pki/payments-gateway.pem":
                (ESTATE / "infra" / "pki" / "public" / "payments-gateway.pem").read_bytes(),
            "app/pki/clearing-partner.crt":
                (ESTATE / "infra" / "pki" / "legacy" / "clearing-partner.crt").read_bytes(),
        },
    }

    manifest = [{
        "Config": "config.json",
        "RepoTags": ["meridian/payments-gateway:3.4.1"],
        "Layers": list(layers),
    }]
    config = {
        "architecture": "amd64", "os": "linux",
        "config": {"Env": ["SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"]},
        "history": [{"created_by": "FROM debian:bullseye-slim"},
                    {"created_by": "RUN apt-get install -y openssl nginx"},
                    {"created_by": "COPY app /app"}],
    }

    with tarfile.open(out, "w") as tf:
        def add(name: str, data: bytes):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        add("manifest.json", json.dumps(manifest, indent=2).encode())
        add("config.json", json.dumps(config, indent=2).encode())
        for layer_name, members in layers.items():
            for member_path, data in members.items():
                add(f"{layer_name.rsplit('/', 1)[0]}/{member_path}", data)
    return out


def build_binaries():
    """Standalone binaries outside any container, for the binary scanner."""
    bindir = ESTATE / "binaries"
    bindir.mkdir(parents=True, exist_ok=True)
    specs = {
        "settlement-daemon": b"OpenSSL 3.0.2 15 Mar 2022\x00",
        "branch-agent": b"wolfSSL 5.6.3\x00mbed TLS 2.28.1\x00",
        "mesh-sidecar": b"BoringSSL\x00X25519MLKEM768\x00",
    }
    for name, marker in specs.items():
        blob = (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56 + marker + b"\x00" * 1024)
        (bindir / name).write_bytes(blob)


# --------------------------------------------------------------------------
# real repositories
# --------------------------------------------------------------------------
def clone_real(shallow_depth: int = 1) -> list[str]:
    REAL.mkdir(parents=True, exist_ok=True)
    cloned = []
    for url, name in REPOS:
        dest = REAL / name
        if dest.exists():
            cloned.append(str(dest))
            continue
        print(f"  cloning {name} ...", flush=True)
        proc = subprocess.run(
            ["git", "clone", "--depth", str(shallow_depth), "--single-branch", url, str(dest)],
            capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"  ! clone failed for {name}: {proc.stderr.strip().splitlines()[-1:]}")
            continue
        shutil.rmtree(dest / ".git", ignore_errors=True)
        cloned.append(str(dest))
    return cloned


def main():
    ap = argparse.ArgumentParser(description="Build the Quantum Atlas scan corpus")
    ap.add_argument("--skip-real", action="store_true",
                    help="skip cloning third-party repositories")
    ap.add_argument("--clean", action="store_true", help="rebuild the estate from scratch")
    args = ap.parse_args()

    if args.clean and ESTATE.exists():
        shutil.rmtree(ESTATE)

    print("building synthetic enterprise estate ...")
    build_sources()
    build_pki()
    build_binaries()
    image = build_container_image()
    print(f"  estate:    {ESTATE}")
    print(f"  container: {image}")

    if not args.skip_real:
        print("cloning real open-source repositories ...")
        for path in clone_real():
            print(f"  real:      {path}")

    files = sum(1 for _ in ESTATE.rglob("*") if _.is_file())
    print(f"\nestate files: {files}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
