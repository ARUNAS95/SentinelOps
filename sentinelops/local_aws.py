"""AWS demos that are hard-pinned to a loopback LocalStack endpoint."""
from __future__ import annotations
import os
from urllib.parse import urlsplit

DEFAULT_ENDPOINT="http://localhost:4566"
DUMMY_ACCESS_KEY="test"
DUMMY_SECRET_KEY="test"

def _local_endpoint(endpoint: str | None=None) -> str:
    value=endpoint or os.getenv("SENTINELOPS_LOCAL_AWS_ENDPOINT",DEFAULT_ENDPOINT)
    parsed=urlsplit(value)
    if (parsed.scheme!="http" or parsed.hostname not in {"localhost","127.0.0.1","::1","localstack"}
            or parsed.port not in {None,4566} or parsed.username or parsed.password
            or parsed.path not in {"","/"} or parsed.query or parsed.fragment):
        raise ValueError("AWS demo endpoint must target localhost or the LocalStack compose service on port 4566.")
    return value.rstrip("/")

def local_client(service: str, endpoint: str | None=None):
    """Create an SDK client with dummy credentials and a loopback-only endpoint."""
    import boto3
    return boto3.client(service,region_name="us-east-1",endpoint_url=_local_endpoint(endpoint),
        aws_access_key_id=DUMMY_ACCESS_KEY,aws_secret_access_key=DUMMY_SECRET_KEY)

def verify_roundtrip(key_id: str, secret_id: str, value: str) -> dict[str,bool]:
    """Exercise KMS encrypt/decrypt and Secrets Manager using LocalStack only."""
    kms=local_client("kms")
    ciphertext=kms.encrypt(KeyId=key_id,Plaintext=value.encode("utf-8"))["CiphertextBlob"]
    plaintext=kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"].decode("utf-8")
    if plaintext!=value:
        raise RuntimeError("KMS roundtrip validation failed.")
    secrets=local_client("secretsmanager")
    secrets.put_secret_value(SecretId=secret_id,SecretString=value)
    stored=secrets.get_secret_value(SecretId=secret_id).get("SecretString")
    if stored!=value:
        raise RuntimeError("Secrets Manager roundtrip validation failed.")
    return {"kms_roundtrip":True,"secrets_manager_roundtrip":True}
