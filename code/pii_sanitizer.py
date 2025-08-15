import os
import re
import hmac
import hashlib
import base64
import random
from typing import Dict, List, Optional, Tuple, Any

import pandas as pd


# for address matching
# Common street suffixes we try to recognize
ADDRESS_SUFFIX = (
    r"(?:Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|"
    r"Highway|Hwy|Terrace|Ter|Place|Pl|Parkway|Pkwy|Circle|Cir|Trail|Trl|Crescent|Cres|Close|Cl)"
)
# House number: digits with optional trailing letter, or simple ranges/fractions like 10-12, 12/3
ADDRESS_HOUSENUM = r"\d{1,6}[A-Za-z]?(?:[/-]\d{1,4})?"
# Street name: allow letters, numbers, spaces, dots, hyphens, apostrophes
ADDRESS_STREET = r"[A-Za-z0-9.\-'\s]+?"


def _b32_short(h: bytes, n: int = 12) -> str:
    """Make a short, URL-safe base32 string from bytes (used to build tokens)."""
    return base64.b32encode(h).decode("ascii").rstrip("=").lower()[:n]


def luhn_valid(num: str) -> bool:
    """Return True if the number passes the Luhn check (credit/debit cards)."""
    s = 0
    alt = False
    for d in reversed(num):
        if not d.isdigit():
            return False
        n = ord(d) - 48
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        s += n
        alt = not alt
    return s % 10 == 0


class SanitizeBot:
    """
    PII sanitizer limited to: names, emails, phones, SSNs, credit cards, addresses.
    - Policy-driven actions (mask/tokenize/scramble/redact)
    - Deterministic tokens via HMAC-SHA256
    - Safe rewriting with re.sub callbacks
    - Optional audit trail
    """

    # Only the six requested types (regex finds candidates; validators confirm)
    PATTERNS: Dict[str, re.Pattern] = {
        "credit_card": re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
        "ssn": re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"),
        "email": re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b"),
        "phone": re.compile(
            r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)\d{3,4}[-.\s]?\d{4}(?!\d)"
        ),
        "address": re.compile(
            rf"\b{ADDRESS_HOUSENUM}\s+{ADDRESS_STREET}\s{ADDRESS_SUFFIX}\b(?:[ ,A-Za-z0-9.\-#]*)?"
        ),
        "name": re.compile(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})\b"),
    }

    TOKEN_PREFIXES = {
        "name": "PERSON_",
        "email": "EMAIL_",
        "phone": "PHONE_",
        "credit_card": "CARD_",
        "ssn": "SSN_",
        "address": "ADDR_",
        "generic": "TOKEN_",
    }

    def __init__(self, **kwargs):
        """Set up config, policies, and HMAC secret used for deterministic tokens."""
        self.config: Dict[str, Any] = kwargs.get("config", {}) or {}
        key = kwargs.get("hmac_secret") or os.environ.get("PII_HMAC_KEY") or "dev-only-ephemeral-key"
        self._hmac_key: bytes = key.encode("utf-8")

        # Policy settings: defaults, per-type, column hints, and allow/deny lists
        self.policy = {
            "defaults": {"action": self.config.get("default_action", "mask")},
            "per_type": self.config.get(
                "per_type",
                {
                    "name": {"action": "tokenize"},
                    "email": {"action": "tokenize"},
                    "phone": {"action": "mask"},
                    "ssn": {"action": "redact"},
                    "credit_card": {"action": "mask"},
                    "address": {"action": "mask"},
                },
            ),
            # e.g., {"email":"email","full_name":"name","phone":"phone","ssn":"ssn","address":"address"}
            "column_hints": self.config.get("column_hints", {}),
            "allowlist": set(self.config.get("allowlist", [])),
            "denylist": set(self.config.get("denylist", [])),
        }

        # To avoid false positives, names from free text are OFF by default
        self.detect_names_in_free_text: bool = bool(self.config.get("detect_names_in_free_text", False))
        self._token_cache: Dict[str, str] = {}

    # ---------------- Public API ----------------

    def shutdown(self):
        """Print a simple message (placeholder hook for cleanup/shutdown)."""
        print("Bot is shutting down.")

    def bot_detect_and_sanitize(self, **kwargs):
        """
        Run detection + sanitization on a list of row dicts.

        Args:
          input_data: list[dict] rows
          query_params:
            - method: optional override for all types (mask|tokenize|scramble|redact)
            - return_audit: bool => return {"data":[...], "audit":[...]}
        """
        qp = kwargs.get("query_params", {}) or {}
        method_override = qp.get("method")
        return_audit = bool(qp.get("return_audit", False))

        df = pd.DataFrame(kwargs["input_data"])  # turn rows into a DataFrame
        sanitized_df, audit_rows = self._sanitize(df, method_override)

        if return_audit:
            return {"data": sanitized_df.to_dict(orient="records"), "audit": audit_rows}
        return sanitized_df.to_dict(orient="records")

    # ---------------- Core sanitize ----------------

    def _sanitize(self, df: pd.DataFrame, method_override: Optional[str]):
        """Walk each cell, apply hinted type first, then generic scan; collect audit per row."""
        audit_rows: List[List[Dict[str, Any]]] = []
        out_df = df.copy(deep=True)

        for idx, row in out_df.iterrows():
            row_audit: List[Dict[str, Any]] = []
            for col in out_df.columns:
                original = row[col]
                text = "" if pd.isna(original) else str(original)

                # 1) Apply column-hinted type first (e.g., "email" column)
                hinted_type = self.policy["column_hints"].get(col)
                if hinted_type in self.PATTERNS:
                    text, col_audit = self._rewrite_with_type(text, hinted_type, method_override, col)
                    row_audit.extend(col_audit)

                # 2) Generic scan (names in free text are optional/off by default)
                for ptype in ["credit_card", "ssn", "email", "phone", "address", "name"]:
                    if ptype == hinted_type:
                        continue
                    if ptype == "name" and not self.detect_names_in_free_text:
                        continue
                    text, col_audit = self._rewrite_with_type(text, ptype, method_override, col)
                    row_audit.extend(col_audit)

                out_df.at[idx, col] = text  # write back sanitized text
            audit_rows.append(row_audit)

        return out_df, audit_rows

    # ---------------- Rewriting helpers ----------------

    def _rewrite_with_type(
        self, text: str, ptype: str, method_override: Optional[str], column: str
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """Find matches of a specific PII type, transform them, and log compact audit info."""
        pattern = self.PATTERNS.get(ptype)
        if not pattern:
            return text, []

        audit_spans: List[Dict[str, Any]] = []

        def _replacement(m: re.Match) -> str:
            """Decide action for the match, validate it, replace it, and record an audit event."""
            raw = m.group(0)

            # Skip if already sanitized or explicitly allowlisted
            if self._looks_sanitized(raw, ptype):
                return raw
            if raw in self.policy["allowlist"]:
                return raw

            # Decide action (denylist forces redact)
            act = "redact" if raw in self.policy["denylist"] else self._action_for(ptype, method_override)

            # Normalize + validate (e.g., Luhn for cards, 9 digits for SSN, etc.)
            normalized, valid = self._normalize_and_validate(ptype, raw, column)
            if not valid:
                return raw  # treat as non-PII if validation fails

            # Apply action
            if act == "tokenize":
                repl = self._tokenize(ptype, normalized)
            elif act == "mask":
                repl = self._mask(ptype, raw, normalized)
            elif act == "scramble":
                repl = self._scramble(raw)
            elif act == "redact":
                repl = "[REDACTED]"
            else:
                repl = raw

            # Save a short audit preview (no raw PII)
            audit_spans.append(
                {
                    "column": column,
                    "type": ptype,
                    "original_preview": raw[:8] + ("…" if len(raw) > 8 else ""),
                    "action": act,
                    "replacement_preview": repl[:12] + ("…" if len(repl) > 12 else ""),
                }
            )
            return repl

        new_text = pattern.sub(_replacement, text)
        return new_text, audit_spans

    def _action_for(self, ptype: str, method_override: Optional[str]) -> str:
        """Choose action: method override > per-type policy > default policy."""
        if method_override:
            return method_override
        return self.policy["per_type"].get(ptype, {}).get("action") or self.policy["defaults"]["action"]

    # ---------------- Validators & normalization ----------------

    def _normalize_and_validate(self, ptype: str, raw: str, column: str) -> Tuple[str, bool]:
        """
        Normalize the match and check if it is a valid instance of this PII type.
        Returns (normalized_value, is_valid).
        """
        if ptype == "credit_card":
            digits = re.sub(r"\D", "", raw)
            return digits, (13 <= len(digits) <= 19 and luhn_valid(digits))
        if ptype == "ssn":
            digits = re.sub(r"\D", "", raw)
            return digits, (len(digits) == 9)
        if ptype == "phone":
            digits = re.sub(r"\D", "", raw)
            # Reject obvious card-like groupings (prevents masking invalid cards as phones)
            if re.search(r"(?:\d{4}[-\s]?){3,}\d{0,4}", raw):
                return digits, False
            return digits, (10 <= len(digits) <= 15)
        if ptype == "email":
            return raw.lower(), True
        if ptype == "address":
            return raw, True
        if ptype == "name":
            hinted = self.policy["column_hints"].get(column) == "name"
            if hinted or self.detect_names_in_free_text:
                return raw.strip(), True
            return raw, False
        return raw, True

    # ---------------- Actions ----------------

    def _tokenize(self, ptype: str, normalized: str) -> str:
        """Create a deterministic token (prefix + short HMAC-SHA256 base32), with simple caching."""
        cache_key = f"{ptype}|{normalized}"
        if cache_key in self._token_cache:
            return self._token_cache[cache_key]
        digest = hmac.new(self._hmac_key, msg=normalized.encode("utf-8"), digestmod=hashlib.sha256).digest()
        token = f"{self.TOKEN_PREFIXES.get(ptype, 'TOKEN_')}{_b32_short(digest)}"
        self._token_cache[cache_key] = token
        return token

    def _mask(self, ptype: str, raw: str, normalized: str) -> str:
        """Mask sensitive parts but keep some utility (e.g., domain, last4, street suffix)."""
        if ptype == "email":
            if "@" in raw:
                user, domain = raw.split("@", 1)
                u = user.strip()
                return (u[0] if u else "*") + "***@" + domain
            return "[MASKED]"
        if ptype == "phone":
            last4 = normalized[-4:] if len(normalized) >= 4 else normalized
            cc_match = re.match(r"^\+?\d{1,3}", raw.replace(" ", ""))
            cc = cc_match.group(0) if cc_match else ""
            return f"{cc}***-***-{last4}"
        if ptype == "credit_card":
            last4 = normalized[-4:] if len(normalized) >= 4 else normalized
            return f"**** **** **** {last4}"
        if ptype == "ssn":
            return "***-**-" + normalized[-4:]
        if ptype == "name":
            parts = raw.split()
            masked_parts = [(p[0] + "***") if len(p) > 0 else "***" for p in parts]
            return " ".join(masked_parts)
        if ptype == "address":
            m = re.match(
                rf"^(?P<num>{ADDRESS_HOUSENUM})\s+(?P<street>{ADDRESS_STREET})\s(?P<suf>{ADDRESS_SUFFIX})\b(?P<trail>.*)$",
                raw,
            )
            if m:
                suf = m.group("suf")
                trail = m.group("trail")
                return f"### *** {suf}{trail}"
            return "[MASKED]"
        return "[MASKED]"

    def _scramble(self, value: str) -> str:
        """Return the same characters shuffled randomly (demo-only)."""
        chars = list(value)
        random.shuffle(chars)
        return "".join(chars)

    def _looks_sanitized(self, text: str, ptype: str) -> bool:
        """Heuristic check to skip values that already look masked/tokenized/redacted."""
        if text.startswith(self.TOKEN_PREFIXES.get(ptype, "TOKEN_")):
            return True
        if text.startswith(tuple(self.TOKEN_PREFIXES.values())):
            return True
        if text in {"[MASKED]", "[REDACTED]"}:
            return True
        if "***" in text or "****" in text:
            return True
        return False
