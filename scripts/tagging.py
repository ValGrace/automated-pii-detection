from __future__ import annotations

from typing import Dict, List

SENSITIVITY_TIERS: Dict[str, str] = {
    "KE_NATIONAL_ID": "RESTRICTED",
    "KE_KRA_PIN": "RESTRICTED",
    "KE_PASSPORT": "RESTRICTED",
    "KE_PHONE_NUMBER": "SENSITIVE",
    "KE_MPESA_CODE": "SENSITIVE",
    "EMAIL_ADDRESS": "SENSITIVE",
    "CREDIT_CARD": "RESTRICTED",
    "IBAN": "RESTRICTED",
    "PERSON_NAME": "SENSITIVE",
    "IP_ADDRESS": "SENSITIVE",

    "KE_NHIF_NUMBER": "SPECIAL_CATEGORY",

    "DATE_OF_BIRTH": "QUASI_IDENTIFIER",
    "KE_VEHICLE_REG": "QUASI_IDENTIFIER",
    "KE_POSTAL_ADDRESS": "QUASI_IDENTIFIER",
    "KE_NSSF_NUMBER": "SENSITIVE",
}   

DEFAULT_TIER = "SENSITIVE"

TAG_PREFIXES: Dict[str, str] = {
    "RESTRICTED": "#RESTRICTED",
    "SENSITIVE": "#PII_SENSITIVE",
    "SPECIAL_CATEGORY": "#PII_SENSITIVE_CATEGORY",
    "QUASI_IDENTIFIER": "#PII_QUASI_IDENTIFIER"
}

def tier_for(entity_type: str) -> str:
    return SENSITIVITY_TIERS.get(entity_type, DEFAULT_TIER)

def tag_entity(entity_type: str) -> List[str]:
   tier = tier_for(entity_type)
   tags = [TAG_PREFIXES[tier]]

   if tier in ("RESTRICTED", "SPECIAL_CATEGORY") and TAG_PREFIXES["SENSITIVE"] not in tags:
       tags.append(TAG_PREFIXES["SENSITIVE"])
   tags.append(f"#ENTITY: {entity_type}")
   return tags