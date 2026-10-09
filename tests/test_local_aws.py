import boto3
import pytest
from sentinelops import local_aws

def test_endpoint_rejects_non_loopback():
    with pytest.raises(ValueError):
        local_aws._local_endpoint("https://kms.us-east-1.amazonaws.com")
    with pytest.raises(ValueError):
        local_aws._local_endpoint("http://169.254.169.254:4566")

def test_client_uses_fixed_dummy_credentials(monkeypatch):
    captured={}
    def fake_client(service,**kwargs):
        captured.update(service=service,**kwargs)
        return object()
    monkeypatch.setattr(boto3,"client",fake_client)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID","must-not-be-used")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY","must-not-be-used")
    local_aws.local_client("kms")
    assert captured["service"]=="kms"
    assert captured["endpoint_url"]=="http://localhost:4566"
    assert captured["aws_access_key_id"]=="test"
    assert captured["aws_secret_access_key"]=="test"

def test_roundtrip_uses_local_services(monkeypatch):
    class KMS:
        def encrypt(self,**kwargs): return {"CiphertextBlob":b"encrypted"}
        def decrypt(self,**kwargs): return {"Plaintext":b"demo"}
    class Secrets:
        def put_secret_value(self,**kwargs): return {}
        def get_secret_value(self,**kwargs): return {"SecretString":"demo"}
    services={"kms":KMS(),"secretsmanager":Secrets()}
    monkeypatch.setattr(local_aws,"local_client",lambda name:services[name])
    assert local_aws.verify_roundtrip("dummy-key","dummy-secret","demo")=={
        "kms_roundtrip":True,"secrets_manager_roundtrip":True}
