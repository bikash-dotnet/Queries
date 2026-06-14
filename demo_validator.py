"""
Demo / Unit Test for mongo_encrypt_validator.py  (v2)
======================================================
Tests multi-field, nested object, and array scenarios — no MongoDB needed.

Run:
    python demo_validator.py
"""

from __future__ import annotations
import base64, json, sys
from datetime import datetime, timezone

try:
    from cryptography.fernet import Fernet
except ImportError:
    sys.exit("❌  cryptography not installed. Run: pip install cryptography")

sys.path.insert(0, ".")
from mongo_encrypt_validator import Status, decrypt_value, validate_document

# ── Key setup ────────────────────────────────────────────────────────────────
KEY       = Fernet.generate_key()          # url-safe base64
KEY_BYTES = base64.urlsafe_b64decode(KEY)
fernet    = Fernet(KEY)

def enc(text: str) -> str:
    """Encrypt and return base64 string (as it would be stored in MongoDB)."""
    return base64.b64encode(fernet.encrypt(text.encode())).decode()

# ── Pre-encrypt some values ───────────────────────────────────────────────────
E_SSN   = enc("123-45-6789")
E_DOB   = enc("1990-06-15")
E_PHONE = enc("+91-9876543210")
E_CVV   = enc("737")
E_EMAIL = enc("alice@example.com")

# ── Mock documents (cover every interesting scenario) ────────────────────────
#
#  Document structure expected:
#  {
#    ssn          : encrypted scalar          (top-level)
#    personal     : { dob: encrypted }        (nested object)
#    contacts     : [{ phone, email }, ...]   (array of objects)
#    payments     : [{ cards: [{ cvv }] }]    (nested array)
#  }
#
DOCS = [
    # ── doc_001: everything valid ────────────────────────────────────────────
    {
        "_id": "doc_001",
        "label": "All fields valid",
        "ssn": E_SSN,
        "personal": {"dob": E_DOB},
        "contacts": [
            {"phone": E_PHONE, "email": E_EMAIL},
            {"phone": E_PHONE, "email": E_EMAIL},
        ],
        "payments": [{"cards": [{"cvv": E_CVV}, {"cvv": E_CVV}]}],
    },

    # ── doc_002: ssn missing → SKIPPED for that field ───────────────────────
    {
        "_id": "doc_002",
        "label": "ssn field absent",
        "personal": {"dob": E_DOB},
        "contacts": [{"phone": E_PHONE, "email": E_EMAIL}],
        "payments": [{"cards": [{"cvv": E_CVV}]}],
    },

    # ── doc_003: ssn null → INVALID ──────────────────────────────────────────
    {
        "_id": "doc_003",
        "label": "ssn is null",
        "ssn": None,
        "personal": {"dob": E_DOB},
        "contacts": [{"phone": E_PHONE, "email": E_EMAIL}],
        "payments": [{"cards": [{"cvv": E_CVV}]}],
    },

    # ── doc_004: personal.dob corrupted → INVALID ────────────────────────────
    {
        "_id": "doc_004",
        "label": "nested personal.dob corrupted",
        "ssn": E_SSN,
        "personal": {"dob": base64.b64encode(b"BAD_CIPHERTEXT_XYZ").decode()},
        "contacts": [{"phone": E_PHONE, "email": E_EMAIL}],
        "payments": [{"cards": [{"cvv": E_CVV}]}],
    },

    # ── doc_005: contacts array — one element has null phone ─────────────────
    {
        "_id": "doc_005",
        "label": "contacts[1].phone is null",
        "ssn": E_SSN,
        "personal": {"dob": E_DOB},
        "contacts": [
            {"phone": E_PHONE, "email": E_EMAIL},
            {"phone": None,    "email": E_EMAIL},   # ← null phone
        ],
        "payments": [{"cards": [{"cvv": E_CVV}]}],
    },

    # ── doc_006: contacts[].email missing on second element ──────────────────
    {
        "_id": "doc_006",
        "label": "contacts[1].email key absent",
        "ssn": E_SSN,
        "personal": {"dob": E_DOB},
        "contacts": [
            {"phone": E_PHONE, "email": E_EMAIL},
            {"phone": E_PHONE},                      # ← no email key
        ],
        "payments": [{"cards": [{"cvv": E_CVV}]}],
    },

    # ── doc_007: payments nested array — one CVV corrupted ───────────────────
    {
        "_id": "doc_007",
        "label": "payments[0].cards[1].cvv corrupted",
        "ssn": E_SSN,
        "personal": {"dob": E_DOB},
        "contacts": [{"phone": E_PHONE, "email": E_EMAIL}],
        "payments": [{
            "cards": [
                {"cvv": E_CVV},
                {"cvv": base64.b64encode(b"CORRUPT").decode()},  # ← bad
            ]
        }],
    },

    # ── doc_008: contacts is empty array → SKIPPED for contacts[] fields ─────
    {
        "_id": "doc_008",
        "label": "contacts is empty array",
        "ssn": E_SSN,
        "personal": {"dob": E_DOB},
        "contacts": [],
        "payments": [{"cards": [{"cvv": E_CVV}]}],
    },

    # ── doc_009: personal is missing entirely ────────────────────────────────
    {
        "_id": "doc_009",
        "label": "personal object missing",
        "ssn": E_SSN,
        "contacts": [{"phone": E_PHONE, "email": E_EMAIL}],
        "payments": [{"cards": [{"cvv": E_CVV}]}],
    },

    # ── doc_010: everything missing (sparse document) ────────────────────────
    {
        "_id": "doc_010",
        "label": "sparse — no encrypted fields at all",
        "name": "Ghost User",
    },
]

# ── Field paths to validate ───────────────────────────────────────────────────
FIELDS = [
    "ssn",
    "personal.dob",
    "contacts[].phone",
    "contacts[].email",
    "payments[].cards[].cvv",
]

# ── Run ───────────────────────────────────────────────────────────────────────
W = 72
counters = {Status.VALID: 0, Status.INVALID: 0, Status.SKIPPED: 0}
all_results: list[dict] = []

print("\n" + "═" * W)
print("  Demo: MongoDB Multi-Field Encrypted Validator")
print("═" * W)
print(f"  Key (first 40 chars): {KEY.decode()[:40]}…")
print(f"  Fields : {', '.join(FIELDS)}")
print(f"  Docs   : {len(DOCS)}")
print("═" * W + "\n")

for doc in DOCS:
    result = validate_document(doc, FIELDS, KEY_BYTES)
    all_results.append(result)
    counters[result["overall_status"]] += 1

    icon = {"VALID": "✅", "INVALID": "❌", "SKIPPED": "⏭️ "}.get(
        result["overall_status"], "?"
    )
    print(f"  {icon} [{result['overall_status']:<7}]  _id={result['_id']}  ({doc.get('label','')})")

    for field_r in result["fields"]:
        for r in field_r["results"]:
            status_icon = {"VALID": "  ✅", "INVALID": "  ❌", "SKIPPED": "  ⏭️ "}.get(
                r["status"], "  ?"
            )
            print(f"    {status_icon}  {r['path']:<40}  {r['reason']}")
    print()

# ── Summary ───────────────────────────────────────────────────────────────────
print("─" * W)
print(f"  ✅  VALID   : {counters[Status.VALID]}")
print(f"  ❌  INVALID : {counters[Status.INVALID]}")
print(f"  ⏭️   SKIPPED : {counters[Status.SKIPPED]}")
print("═" * W)

# ── JSON output ───────────────────────────────────────────────────────────────
summary = {
    "meta": {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "fields_validated": FIELDS,
        "total_documents": len(DOCS),
    },
    "counters": {
        "valid":   counters[Status.VALID],
        "invalid": counters[Status.INVALID],
        "skipped": counters[Status.SKIPPED],
    },
    "results": all_results,
}
with open("demo_results.json", "w") as f:
    json.dump(summary, f, indent=2, default=str)
print("\n  📄  Full JSON results → demo_results.json\n")
