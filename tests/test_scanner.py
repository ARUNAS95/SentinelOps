from sentinelops.scanner import scan_cloud, scan_text

def test_public_bucket_and_wildcard_iam():
    results=scan_cloud({"buckets":[{"name":"sample","public_access_block":{"block_public_policy":False}}],
        "iam_policies":[{"name":"worker","statements":[{"effect":"Allow","action":"*","resource":["arn:demo"]}]}]})
    assert {f.remediation for f in results}=={"enable_public_access_block","scope_iam_policy"}
    assert all(f.severity.value in {"critical","high"} for f in results)

def test_secret_value_is_redacted():
    secret="AKIAABCDEFGHIJKLMNOP"
    result=scan_text(f"AWS_KEY={secret}","sample.env")
    assert len(result)==1 and secret not in result[0].model_dump_json()
    assert "redacted" in result[0].evidence

def test_safe_bucket_has_no_finding():
    cfg={"buckets":[{"name":"safe","encryption":"AES256","public_access_block":{
        "block_public_acls":True,"ignore_public_acls":True,"block_public_policy":True,"restrict_public_buckets":True}}]}
    assert scan_cloud(cfg)==[]
