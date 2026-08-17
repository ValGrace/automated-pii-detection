from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional


@dataclass
class Match:
    entity_type: str
    value: str
    start: int
    end: int
    confidence: float

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"Match(entity_type={self.entity_type!r}, value={self.value!r}, "
            f"confidence={self.confidence:.2f})"
        )


@dataclass
class Recognizer:
    entity_type: str
    pattern: "re.Pattern[str]"
    base_confidence: float
    context_words: List[str] = field(default_factory=list)
    context_window: int = 30  # characters to look back/forward for context
    context_boost: float = 0.25
    validator: Optional[Callable[[str], bool]] = None

    def find(self, text: str) -> List[Match]:
        matches: List[Match] = []
        for m in self.pattern.finditer(text):
            value = m.group(0)
            if self.validator is not None and not self.validator(value):
                continue
            confidence = self.base_confidence
            if self.context_words and self._has_context(text, m.start(), m.end()):
                confidence = min(1.0, confidence + self.context_boost)
            matches.append(
                Match(
                    entity_type=self.entity_type,
                    value=value,
                    start=m.start(),
                    end=m.end(),
                    confidence=round(confidence, 2),
                )
            )
        return matches

    def _has_context(self, text: str, start: int, end: int) -> bool:
        lo = max(0, start - self.context_window)
        hi = min(len(text), end + self.context_window)
        window = text[lo:hi].lower()
        return any(word in window for word in self.context_words)


# Validators

def _luhn_check(number: str) -> bool:
    """Standard Luhn checksum, used for credit/debit card validation."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 12:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# Kenya-specific recognizers

KENYA_RECOGNIZERS: List[Recognizer] = [
    Recognizer(
        entity_type="KE_KRA_PIN",
        pattern=re.compile(r"\b[A-Za-z]\d{9}[A-Za-z]\b"),
        base_confidence=0.85,
        context_words=["kra", "pin", "tax", "pin no", "pin number"],
    ),
    Recognizer(
        entity_type="KE_PHONE_NUMBER",
        pattern=re.compile(
            r"(?:\+254|254|0)(7[0-9]{8}|1[01][0-9]{7})\b"
        ),
        base_confidence=0.8,
        context_words=["phone", "mobile", "simu", "tel", "contact", "cell"],
    ),
    Recognizer(
        entity_type="KE_NATIONAL_ID",
        # 7-8 digit numbers are ambiguous on their own -> low base confidence,
        # relies heavily on context words to become a real detection.
        pattern=re.compile(r"\b\d{7,8}\b"),
        base_confidence=0.35,
        context_words=[
            "national id", "id no", "id number", "id:", "identity card",
            "huduma", "kitambulisho",
        ],
        context_boost=0.5,
    ),
    Recognizer(
        entity_type="KE_MPESA_CODE",
        # Safaricom M-Pesa transaction codes: 2 letters + 8 alphanumeric.
        # Format has shifted historically -- keep this pattern versioned
        # and easy to update as new samples come in.
        pattern=re.compile(r"\b[A-Z]{2}[A-Z0-9]{8}\b"),
        base_confidence=0.55,
        context_words=["mpesa", "m-pesa", "transaction", "ref", "confirmation code"],
        context_boost=0.35,
    ),
    Recognizer(
        entity_type="KE_NHIF_NUMBER",
        pattern=re.compile(r"\b\d{6,9}\b"),
        base_confidence=0.25,
        context_words=["nhif", "health insurance", "medical cover"],
        context_boost=0.6,
    ),
    Recognizer(
        entity_type="KE_NSSF_NUMBER",
        pattern=re.compile(r"\b\d{6,10}\b"),
        base_confidence=0.25,
        context_words=["nssf", "pension", "social security"],
        context_boost=0.6,
    ),
    Recognizer(
        entity_type="KE_PASSPORT",
        pattern=re.compile(r"\b[A-Za-z]\d{7}\b"),
        base_confidence=0.6,
        context_words=["passport"],
        context_boost=0.3,
    ),
    Recognizer(
        entity_type="KE_VEHICLE_REG",
        pattern=re.compile(r"\bK[A-Z]{2}\s?\d{3}[A-Z]\b"),
        base_confidence=0.75,
        context_words=["number plate", "reg no", "vehicle"],
    ),
    Recognizer(
        entity_type="KE_POSTAL_ADDRESS",
        pattern=re.compile(r"\bP\.?O\.?\s?BOX\s?\d{1,6}-?\d{0,5}\b", re.IGNORECASE),
        base_confidence=0.7,
    ),
]


# Generic / global recognizers


GENERIC_RECOGNIZERS: List[Recognizer] = [
    Recognizer(
        entity_type="EMAIL_ADDRESS",
        pattern=re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
        base_confidence=0.95,
    ),
    Recognizer(
        entity_type="IP_ADDRESS",
        pattern=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
        base_confidence=0.7,
    ),
    Recognizer(
        entity_type="CREDIT_CARD",
        pattern=re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        base_confidence=0.5,
        validator=_luhn_check,
    ),
    Recognizer(
        entity_type="DATE_OF_BIRTH",
        pattern=re.compile(
            r"\b\d{1,2}[/-]\d{1,2}[/-](?:19|20)\d{2}\b|\b(?:19|20)\d{2}[/-]\d{1,2}[/-]\d{1,2}\b"
        ),
        base_confidence=0.4,
        context_words=["dob", "date of birth", "born"],
        context_boost=0.5,
    ),
    Recognizer(
        entity_type="IBAN",
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
        base_confidence=0.6,
        context_words=["iban", "swift", "bank"],
    ),
    Recognizer(
        entity_type="PERSON_NAME",
        # Placeholder heuristic: two-to-three consecutive capitalized
        # tokens. This is intentionally coarse -- swap in a proper NER
        # backend (spaCy / Presidio) via `pii_engine.ner_backend` for
        # production-quality free-text name detection.
        pattern=re.compile(r"\b[A-Z][a-z]+(?:\s[A-Z][a-z]+){1,2}\b"),
        base_confidence=0.3,
        context_words=["name", "customer", "client", "applicant", "jina"],
        context_boost=0.35,
    ),
]

ENTITY_REGISTRY: List[Recognizer] = KENYA_RECOGNIZERS + GENERIC_RECOGNIZERS


def scan_text(text: str, min_confidence: float = 0.5) -> List[Match]:
    """Run every registered recognizer over `text` and return matches
    at or above `min_confidence`, sorted by position then confidence
    (highest first, so overlap resolution can prefer stronger hits)."""
    if not isinstance(text, str) or not text:
        return []
    results: List[Match] = []
    for recognizer in ENTITY_REGISTRY:
        results.extend(recognizer.find(text))
    filtered = [m for m in results if m.confidence >= min_confidence]
    filtered.sort(key=lambda m: (m.start, -m.confidence))
    return _resolve_overlaps(filtered)


def _resolve_overlaps(matches: List[Match]) -> List[Match]:
    """When multiple recognizers hit the same span (e.g. a National ID
    pattern also matching inside an NHIF pattern), keep only the
    highest-confidence match per overlapping region."""
    resolved: List[Match] = []
    for m in matches:
        overlap = next(
            (r for r in resolved if not (m.end <= r.start or m.start >= r.end)),
            None,
        )
        if overlap is None:
            resolved.append(m)
        elif m.confidence > overlap.confidence:
            resolved.remove(overlap)
            resolved.append(m)
    resolved.sort(key=lambda m: m.start)
    return resolved
