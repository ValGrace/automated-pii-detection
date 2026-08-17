from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from typing import Dict, Optional


DEFAULT_STRATEGY_BY_TIER = {
    "RESTRICTED": "hash",
    "SPECIAL_CATEGORY": "redact",
    "SENSITIVE": "token",
    "QUASI_IDENTIFIER": "generalize",
}


def hash_value(value: str, salt: str) -> str:
    """One-way, deterministic HMAC-SHA256 hash. Use for fields that are
    only ever needed as a join key downstream, never in original form."""
    digest = hmac.new(salt.encode("utf-8"), value.encode("utf-8"), hashlib.sha256)
    return f"HASH:{digest.hexdigest()[:24]}"


def token_mask(value: str, keep_last: int = 4, mask_char: str = "*") -> str:
    """Format-preserving partial mask, e.g. '0712345678' -> '******5678'."""
    if len(value) <= keep_last:
        return mask_char * len(value)
    return mask_char * (len(value) - keep_last) + value[-keep_last:]


def redact(value: str) -> str:
    return "[REDACTED]"


def generalize(value: str, entity_type: str) -> str:
    """Very small generalization ruleset -- extend per field as needed."""
    if entity_type == "DATE_OF_BIRTH":
        # Keep only the year -> reduces a direct DOB to an age band proxy.
        for sep in ("/", "-"):
            if sep in value:
                parts = value.split(sep)
                year = next((p for p in parts if len(p) == 4), None)
                if year:
                    return f"YEAR:{year}"
        return "[GENERALIZED]"
    if entity_type == "KE_POSTAL_ADDRESS":
        return "[P.O. BOX - GENERALIZED]"
    if entity_type == "KE_VEHICLE_REG":
        return value[:3] + "***" if len(value) >= 3 else "[GENERALIZED]"
    return "[GENERALIZED]"


@dataclass
class TokenVault:
    """In-memory reversible token vault. In production this backs onto
    an access-controlled, encrypted store (e.g. Postgres + KMS-wrapped
    column, or HashiCorp Vault) -- kept as a pluggable interface here."""

    _forward: Dict[str, str] = field(default_factory=dict)
    _reverse: Dict[str, str] = field(default_factory=dict)

    def tokenize(self, value: str) -> str:
        if value in self._forward:
            return self._forward[value]
        token = f"TKN:{secrets.token_hex(8)}"
        self._forward[value] = token
        self._reverse[token] = value
        return token

    def detokenize(self, token: str) -> Optional[str]:
        return self._reverse.get(token)


def mask_value(
    value: str,
    entity_type: str,
    tier: str,
    salt: str = "change-me-per-deployment",
    strategy: Optional[str] = None,
    vault: Optional[TokenVault] = None,
) -> str:
    """Apply the appropriate masking strategy for a value given its
    entity type and sensitivity tier. Pass `strategy` to override the
    tier's default (e.g. force 'vault_token' for a field that
    legitimately needs re-identification under a lawful basis)."""
    strategy = strategy or DEFAULT_STRATEGY_BY_TIER.get(tier, "hash")
    value = str(value)

    if strategy == "hash":
        return hash_value(value, salt)
    if strategy == "token":
        return token_mask(value)
    if strategy == "vault_token":
        if vault is None:
            raise ValueError("vault_token strategy requires a TokenVault instance")
        return vault.tokenize(value)
    if strategy == "generalize":
        return generalize(value, entity_type)
    if strategy == "redact":
        return redact(value)

    raise ValueError(f"Unknown masking strategy: {strategy!r}")
