
import os
import sys
from pathlib import Path
import pytest

# Make ../code importable
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "code"))

from pii_sanitizer import SanitizeBot


def make_bot(**overrides):
    cfg = {
        "default_action": "mask",
        "per_type": {
            "name": {"action": "tokenize"},
            "email": {"action": "tokenize"},
            "phone": {"action": "mask"},
            "ssn": {"action": "redact"},
            "credit_card": {"action": "mask"},
            "address": {"action": "mask"},
        },
        "column_hints": {
            "name": "name",
            "full_name": "name",
            "email": "email",
            "phone": "phone",
            "ssn": "ssn",
            "address": "address",
        },
        # names in free text OFF by default to reduce false positives
        # "detect_names_in_free_text": True,
        "allowlist": [],
        "denylist": [],
    }
    cfg.update(overrides)
    return SanitizeBot(config=cfg, hmac_secret="test-secret-key")


def sanitize(bot, rows, **qp):
    q = {"return_audit": True}
    q.update(qp)
    return bot.bot_detect_and_sanitize(input_data=rows, query_params=q)


def find_audit_types(audit_row):
    return [e.get("type") for e in audit_row]


def test_email_tokenization_and_determinism():
    bot = make_bot()
    rows = [
        {"email": "alice@example.com"},
        {"email": "alice@example.com"},
    ]
    out = sanitize(bot, rows)
    e1 = out["data"][0]["email"]
    e2 = out["data"][1]["email"]
    assert e1.startswith("EMAIL_")
    assert e1 == e2, "same input should map to same token for same secret"

    # New bot with same secret -> same token
    bot2 = make_bot()
    out2 = sanitize(bot2, [{"email": "alice@example.com"}])
    assert out2["data"][0]["email"] == e1

    # Different secret -> different token
    bot3 = SanitizeBot(config=bot.config, hmac_secret="another-secret")
    out3 = sanitize(bot3, [{"email": "alice@example.com"}])
    assert out3["data"][0]["email"] != e1


def test_phone_masking_formats():
    bot = make_bot()
    rows = [
        {"phone": "+1 415-555-2671"},
        {"phone": "(212) 555-7890"},
    ]
    out = sanitize(bot, rows)
    assert out["data"][0]["phone"].endswith("2671")
    assert "+141" in out["data"][0]["phone"]  # country code preserved if present
    assert out["data"][1]["phone"].endswith("7890")
    assert out["data"][1]["phone"].startswith("***-***-")  # no country code


def test_credit_card_masking_with_luhn():
    bot = make_bot()
    rows = [
        {"note": "valid 4111 1111 1111 1111"},  # Visa test number (passes Luhn)
        {"note": "invalid 4111 1111 1111 1112"},  # fails Luhn
    ]
    out = sanitize(bot, rows)
    # valid should be masked to last4 only
    assert "**** **** **** 1111" in out["data"][0]["note"]
    # invalid should remain unchanged
    assert "4111 1111 1111 1112" in out["data"][1]["note"]


def test_ssn_redaction_strict_and_invalid_is_ignored():
    bot = make_bot()
    rows = [
        {"ssn": "123-45-6789"},  # valid -> redact
        {"note": "SSN 987-65-4320"},  # invalid per strict pattern -> unchanged
    ]
    out = sanitize(bot, rows)
    assert out["data"][0]["ssn"] == "[REDACTED]"
    assert "987-65-4320" in out["data"][1]["note"]

    # No audit event for the invalid SSN
    types = sum((find_audit_types(r) for r in out["audit"]), [])
    assert "ssn" in types  # for the valid one
    # ensure the invalid didn't create an ssn audit in row 2
    assert out["audit"][1] == [] or all(e["type"] != "ssn" for e in out["audit"][1])


def test_address_masking_including_alphanumeric_house_numbers_and_suffixes():
    bot = make_bot()
    rows = [
        {"address": "742 Evergreen Terrace, Springfield, IL 62704"},
        {"note": "Ship to 221B Baker Street, London NW1 6XE."},
    ]
    out = sanitize(bot, rows)
    # Both should have "### ***" and retain suffix e.g., Terrace/Street
    assert "### ***" in out["data"][0]["address"]
    assert "Terrace" in out["data"][0]["address"]
    assert "### ***" in out["data"][1]["note"]
    assert "Street" in out["data"][1]["note"]


def test_name_detection_column_hints_only_by_default():
    bot = make_bot()
    rows = [
        {"full_name": "John Doe", "note": "Contact John Doe for details."},
    ]
    out = sanitize(bot, rows)
    # hinted column should tokenize
    assert out["data"][0]["full_name"].startswith("PERSON_")
    # free text should remain as-is when detect_names_in_free_text is False
    assert "John Doe" in out["data"][0]["note"]


def test_per_request_override_method_applies_to_all_types():
    bot = make_bot()
    rows = [
        {
            "name": "Alice Johnson",
            "email": "alice@example.com",
            "phone": "+1 415-555-2671",
            "ssn": "123-45-6789",
            "address": "1600 Pennsylvania Ave NW, Washington, DC 20500",
            "note": "Card 4111 1111 1111 1111",
        }
    ]
    out = sanitize(bot, rows, method="redact")
    # Everything detected should be fully redacted
    s = json_repr = out["data"][0]
    for v in s.values():
        if isinstance(v, str):
            assert "[REDACTED]" in v or v == "[REDACTED]" or v == ""


def test_idempotency_running_twice_is_stable():
    bot = make_bot()
    rows = [
        {"email": "alice@example.com", "note": "Call +1 415-555-2671"},
    ]
    first = sanitize(bot, rows)["data"]
    second = sanitize(bot, first)["data"]
    assert second == first  # sanitizing sanitized data should not change it further


def test_audit_structure_and_keys_present():
    bot = make_bot()
    rows = [
        {"email": "alice@example.com", "phone": "+1 415-555-2671"},
    ]
    out = sanitize(bot, rows)
    audit = out["audit"][0]
    assert len(audit) >= 2
    for evt in audit:
        assert set(["column", "type", "action", "original_preview", "replacement_preview"]).issubset(evt.keys())


def test_allowlist_and_denylist_behavior():
    bot = make_bot(
        allowlist=["public@example.com"],
        denylist=["bob@example.com"],
    )
    rows = [
        {"note": "contact public@example.com and bob@example.com"},
    ]
    out = sanitize(bot, rows)
    text = out["data"][0]["note"]
    # Allowlisted email unchanged
    assert "public@example.com" in text
    # Denylisted email redacted
    assert "[REDACTED]" in text and "bob@example.com" not in text
