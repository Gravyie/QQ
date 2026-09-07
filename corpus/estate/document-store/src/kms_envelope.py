"""Cloud KMS envelope encryption for the document store."""
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
