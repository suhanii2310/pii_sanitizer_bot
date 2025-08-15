# PII Sanitization Bot — Project Overview

A clear, simple overview of how the bot detects and protects sensitive data while keeping it useful.

---

## Objective

Build a simple, reliable bot that:

- Finds personal info in data automatically.
- Hides it safely (mask, tokenize, redact, or scramble).
- Keeps the data useful and the structure the same.
- Shows exactly what changed (audit log).
- Is easy to try (demo UI) and easy to call (API).

---

## Scope

**What’s included**

- Detects 6 types: **names, emails, phones, SSNs (strict), credit cards (with validity check), addresses**.
- Works on JSON row data (CSV can be read and converted).
- Actions per type: **mask, tokenize, redact, scramble** (tokens are deterministic using a secret).
- Policy controls: per-type defaults, run-time override, column hints, allowlist/denylist.
- Outputs: sanitized rows + optional audit (short previews only).

**What’s not included (current version)**

- Non-U.S. government IDs or global variations of SSNs.
- Heavy ML/NLP name detection or multilingual NER (we use targeted patterns).
- Full international address parsing (we use a curated street-suffix list).
- Reversible tokens (these are one-way by design).

---

## Key Contributions

- **SanitizeBot library** — detects PII, applies safe changes, and records an audit.
- **Deterministic tokenization** — same input + same secret → same token.
- **Better address handling** — supports house numbers like **221B** and common street endings.
- **Flask API** — `POST /api/sanitize` for quick integration.
- **Frontend demo** — paste/upload JSON → see **Before/After** + **Audit** and download results.
- **Tests & sample data** — quick way to validate behavior.
- **Docs** — clear setup, usage, and design notes.

---

## What the bot does

- **Scans your data** (JSON rows / table-like) and **finds PII**.
- **Protects** each PII match using a rule you choose per type: **mask**, **tokenize**, **redact**, or **scramble**.
- **Returns** the cleaned data and (optionally) an **audit log** showing exactly what was changed.

---

## What it detects (exactly 6 types)

- **Name**
- **Email**
- **Phone number**
- **SSN** (U.S., **strict**: ignores invalid ones like 987-65-4320 by design)
- **Credit card** (13–19 digits, **Luhn** validated)
- **Address** (house number incl. “221B”, street name, and a known suffix like Street/St/Rd/Drive/Terrace, etc.)

---

## What “protect” means (actions)

- **Mask** – hide most characters but keep a little utility
  - Email → `a***@example.com`
  - Phone → `+141***-***-2671`
  - Card → `**** **** **** 1111`
  - SSN → `***-**-6789`
  - Address → `### *** Street, London…`
  - Name → `J*** D***`
- **Tokenize** – swap with a stable, one-way tag (uses HMAC-SHA256)
  - `alice@example.com` → `EMAIL_ab12cd34efgh`
- **Redact** – replace entirely with `[REDACTED]` (default for SSN)
- **Scramble** – jumble characters (for demos only)

> **Decision order**
>
> 1. Per-request override: `method="mask" | "tokenize" | "redact" | "scramble"`
> 2. Per-type policy (defaults): name/tokenize, email/tokenize, phone/mask, ssn/redact, card/mask, address/mask
> 3. Default action fallback: `mask`

You can also provide:

- **column_hints** (e.g., `"full_name": "name"`) to reduce false positives.
- **allowlist** (never change these exact values).
- **denylist** (always redact these exact values).

---

## How detection works (brief)

- Uses carefully chosen **regex patterns** per type.
- Extra **validators**:
  - Credit cards must pass **Luhn**.
  - SSNs are **strict** (invalid prefixes like 9xx/000/666 are ignored).
- **Addresses** support alphanumeric house numbers (e.g., 221B) and a curated set of street suffixes.
- **Names** are conservative by default (mainly when a column is hinted as a name) to avoid false positives.

---

## Tokens are deterministic (and safe)

- Token = `PREFIX + base32(HMAC_SHA256(secret, normalized_value))[:12]`
- Same input + same secret → same token.
- One-way: you can’t get the original back from the token.

---

## Idempotent & careful

- Won’t “double-sanitize” text that already looks masked/tokenized.
- Short **audit previews** only—no raw PII is logged.

---

## Results / Impacts

- **Lower privacy risk**: sensitive fields are protected right away.
- **Data stays useful**: tokens and masking keep joins and analysis working.
- **Clear accountability**: audit shows what changed and where.
- **Fast adoption**: tiny API + simple UI → easy to demo and integrate.
- **Flexible control**: adjust per-type rules without code changes.

---

## Next steps / Handoff notes

**Engineering**

- Local run: `python app.py` → open `http://127.0.0.1:5000/`.
- Production: run behind Gunicorn/Nginx; add health checks and metrics.
- Secrets: set `PII_HMAC_KEY` via a secret manager; rotate regularly.
- Safety: add rate limits and request size caps; log only **sanitized** data.
- Scale: add batch/stream processing if needed; extend address rules as formats appear.

**Quality**

- Add unit tests for edge cases (multiple PII per cell, overlaps).
- Track false positives/negatives with synthetic datasets.

**Optional features**

- More PII types (e.g., DOB, passport, IBAN) with validators.
- Optional ML name detection if higher recall is needed.
- Log “skipped invalid SSN” events (still don’t mask invalid SSNs).

**Deployment artifacts**

- `code/pii_sanitizer.py` — core library.
- `app.py` — API + static server for demo UI.
- `frontend/` — `index.html`, `app.js`, `styles.css`.
- `tests/test_sanitizer.py` — example runner that saves outputs + audit.
- `PII_HMAC_KEY` — required in prod (store securely).

---

## Tiny example

**Input**

```json
[
  {
    "name": "Alice Johnson",
    "email": "alice@example.com",
    "note": "Card 4111 1111 1111 1111; call +1 415-555-2671."
  }
]
```

**Output (defaults)**

```json
[
  {
    "name": "PERSON_ayvt4ejqdwcm",
    "email": "EMAIL_lwz32jgq2ssh",
    "note": "Card **** **** **** 1111; call +141***-***-2671."
  }
]
```

**Audit (preview)**

```json
[
  [
    { "column": "name", "type": "name", "action": "tokenize" },
    { "column": "email", "type": "email", "action": "tokenize" },
    { "column": "note", "type": "credit_card", "action": "mask" },
    { "column": "note", "type": "phone", "action": "mask" }
  ]
]
```

---

## Live Demo

This is a **live demo to show how the bot works** (paste/upload JSON, click _Sanitize_, and see **Before/After** with an **Audit**).

**Two ways to open it:**

1. **Run locally (recommended for full API):**

   python app.py

   Then open: **http://127.0.0.1:5000/**

2. **Hosted demo (GitHub Pages):**  
   https://suhanii2310.github.io/pii_sanitizer_bot/page/

> The GitHub Pages demo is UI-only. For real processing, run the Flask API locally (or deploy it) and point the UI to that endpoint.

---

## TL;DR

The bot finds six kinds of PII, protects them according to your policy, gives you a clean dataset + an audit trail, and uses deterministic tokens so analytics still work.
