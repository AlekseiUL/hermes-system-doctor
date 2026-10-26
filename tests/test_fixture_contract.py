import hashlib, json
from pathlib import Path

def test_versioned_synthetic_contract():
    root=Path(__file__).resolve().parents[1]
    manifest=json.loads((root/'tests/fixture-contract-v1.json').read_text())
    assert manifest['fixture_contract_version']==1
    assert manifest['kind']=='synthetic-offline'
    for name,digest in manifest['files'].items():
        assert hashlib.sha256((root/name).read_bytes()).hexdigest()==digest, name
