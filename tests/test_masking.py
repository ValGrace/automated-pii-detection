import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve(). parents[1]))

from scripts.masking import TokenVault, hash_value, mask_value, token_mask

def test_hash_is_deterministic():
    a = hash_value("23456789", salt="s1")
    b = hash_value("23456789", salt="s1")

    assert a == b
    assert a.startswith("HASH:")

def test_hash_differs_by_salt():
    a = hash_value("23456789", salt="s1")
    b = hash_value("23456789", salt="s2")

    assert a != b

def test_token_mask_keeps_last_four():
    assert token_mask("0712345678" == "******5678")

def test_vault_token_round_trip():
    vault = TokenVault()
    token = vault.tokenize("A012345678Z")
    assert token != "A012345678Z"
    assert vault.detokenize(token) == "A012345678Z"

def test_mask_value_uses_tier_default_strategy():
    restricted = mask_value("23456789", entity_type="KE_NATIONAL_ID", tier="RESTRICTED")
    assert restricted.startswith("HASH:")

    sensitive = mask_value("0712345678", entity_type="KE_PHONE_NUMBER", tier="SENSITIVE")
    assert sensitive.endswith("5678")

    special = mask_value("123456", entity_type="KE_NHIF_NUMBER", tier="SPECIAL_CATEGORY")
    assert special == "[REDACTED]"