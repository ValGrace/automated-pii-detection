import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.detectors import scan_text


def _entities(text, min_confidence=0.5):
    return {m.entity_type for m in scan_text(text, min_confidence=min_confidence)}


def test_kra_pin_detected():
    assert "KE_KRA_PIN" in _entities("Please quote KRA PIN A012345678Z on the invoice.")


def test_kenyan_phone_local_format():
    assert "KE_PHONE_NUMBER" in _entities("Call the customer on 0712345678 today.")


def test_kenyan_phone_international_format():
    assert "KE_PHONE_NUMBER" in _entities("Contact: +254722334455")


def test_national_id_needs_context():
    # Bare 8-digit number with no context should NOT confidently fire.
    assert "KE_NATIONAL_ID" not in _entities("Order number 23456789 shipped today.")
    # Same number with context words should fire.
    assert "KE_NATIONAL_ID" in _entities("National ID No: 23456789")


def test_mpesa_code_with_context():
    assert "KE_MPESA_CODE" in _entities("M-Pesa confirmation code QGH72K9X4M received.")


def test_vehicle_registration():
    assert "KE_VEHICLE_REG" in _entities("The vehicle KDA123B was seen near the gate.")


def test_email_detected():
    assert "EMAIL_ADDRESS" in _entities("Reach me at jane.doe@example.com anytime.")


def test_passport_number():
    assert "KE_PASSPORT" in _entities("Passport number A1234567 is required for travel.")


def test_no_false_positive_on_plain_sentence():
    assert _entities("The weather in Nairobi is sunny today.") == set()


def test_overlap_resolution_keeps_highest_confidence():
   
    matches = scan_text("M-Pesa confirmation code QGH72K9X4M received.", min_confidence=0.3)
    spans_for_code = [m for m in matches if m.value == "QGH72K9X4M"]
    assert len(spans_for_code) == 1
    assert spans_for_code[0].entity_type == "KE_MPESA_CODE"
