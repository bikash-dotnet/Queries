"""
MongoDB Encrypted Field Validator  (v2 — multi-field, nested objects, arrays)
==============================================================================
Validates one or more encrypted fields in MongoDB documents.

Path syntax (--fields / fields config)
---------------------------------------
  ssn                        → top-level scalar
  personal.ssn               → nested object  (dot notation)
  contacts[].email           → array of scalars / objects  ([])
  addresses[].zip            → encrypted field inside each array element
  payments[].cards[].cvv     → multi-level array nesting

Validation rules per resolved value
-------------------------------------
  SKIPPED  – path segment not found anywhere in the document
  INVALID  – path found but value is null / empty
  INVALID  – path found but decryption fails with the provided key
  VALID    – path found and decrypts successfully

CLI usage
---------
  # single field
  python mongo_encrypt_validator.py \\
      --uri mongodb://localhost:27017 --db mydb --collection users \\
      --fields ssn \\
      --key <BASE64_KEY>

  # multiple fields (space-separated)
  python mongo_encrypt_validator.py ... \\
      --fields ssn personal.dob contacts[].phone payments[].cards[].cvv

  # fields from a JSON config file
  python mongo_encrypt_validator.py ... --fields-config fields.json

  # fields.json example:
  # ["ssn", "personal.dob", "contacts[].phone", "payments[].cards[].cvv"]

Generate a Fernet key:
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Generator

# ── Optional dependencies ────────────────────────────────────────────────────
try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
except ImportError:
    sys.exit("❌  pymongo not installed. Run: pip install pymongo")

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("❌  cryptography not installed. Run: pip install cryptography")

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Sentinel for "segment not found" ─────────────────────────────────────────
_MISSING = object()


# ════════════════════════════════════════════════════════════════════════════
# Status
# ════════════════════════════════════════════════════════════════════════════
class Status(str, Enum):
    VALID   = "VALID"
    INVALID = "INVALID"
    SKIPPED = "SKIPPED"


# ════════════════════════════════════════════════════════════════════════════
# Path resolver  —  handles dots and [] array wildcards
# ════════════════════════════════════════════════════════════════════════════
def _parse_path(field_path: str) -> list[str | None]:
    """
    Convert a path string into a list of segments.
    '[]' becomes None (array wildcard).

    Examples
    --------
    "ssn"                       → ["ssn"]
    "personal.dob"              → ["personal", "dob"]
    "contacts[].email"          → ["contacts", None, "email"]
    "payments[].cards[].cvv"    → ["payments", None, "cards", None, "cvv"]
    """
    # Replace []. and [] with a separator
    normalised = field_path.replace("[].", ".[].").replace("[]", ".[]")
    raw_parts = normalised.split(".")
    segments: list[str | None] = []
    for part in raw_parts:
        if part == "[]":
            segments.append(None)   # None == array wildcard
        elif part:
            segments.append(part)
    return segments


def _resolve_values(
    node: Any,
    segments: list[str | None],
) -> Generator[tuple[str, Any], None, None]:
    """
    Walk *node* following *segments* and yield (resolved_path, value) for
    every leaf reached.

    Yields (_MISSING sentinel, path_str) when a segment is absent so the
    caller can distinguish "not found" from "found but null".

    Params
    ------
    node      : current data node (dict, list, scalar, or None)
    segments  : remaining path segments

    Yields
    ------
    (path_label: str, value: Any | _MISSING)
    """
    yield from _walk(node, segments, "")


def _walk(
    node: Any,
    segments: list[str | None],
    current_path: str,
) -> Generator[tuple[str, Any], None, None]:
    # ── All segments consumed → this node is the leaf value ─────────────────
    if not segments:
        yield (current_path, node)
        return

    seg, *rest = segments

    # ── Array wildcard ───────────────────────────────────────────────────────
    if seg is None:
        if not isinstance(node, list):
            # Expected array, found something else — treat as missing
            yield (current_path + "[]", _MISSING)
            return
        if not node:
            # Empty array — nothing to validate, treat as skipped
            yield (current_path + "[]", _MISSING)
            return
        for idx, item in enumerate(node):
            yield from _walk(item, rest, f"{current_path}[{idx}]")
        return

    # ── Named key ────────────────────────────────────────────────────────────
    label = f"{current_path}.{seg}" if current_path else seg

    if not isinstance(node, dict):
        yield (label, _MISSING)
        return

    if seg not in node:
        yield (label, _MISSING)
        return

    yield from _walk(node[seg], rest, label)


# ════════════════════════════════════════════════════════════════════════════
# Decryption
# ════════════════════════════════════════════════════════════════════════════
class DecryptionError(Exception):
    """Raised when all decryption attempts fail."""


def _try_fernet(key_bytes: bytes, ciphertext: bytes) -> bytes:
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(fernet_key).decrypt(ciphertext)


def _try_aesgcm(key_bytes: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) < 28:
        raise ValueError("Ciphertext too short for AES-GCM (need ≥ 28 bytes).")
    nonce, payload = ciphertext[:12], ciphertext[12:]
    return AESGCM(key_bytes).decrypt(nonce, payload, None)


def decrypt_value(raw: Any, key_bytes: bytes) -> bytes:
    """
    Decode base64 → decrypt via Fernet then AES-256-GCM.
    Raises DecryptionError if both fail.
    """
    if isinstance(raw, str):
        try:
            ciphertext = base64.b64decode(raw)
        except Exception as exc:
            raise DecryptionError(f"Not valid base64: {exc}") from exc
    elif isinstance(raw, bytes):
        ciphertext = raw
    else:
        raise DecryptionError(
            f"Unsupported value type '{type(raw).__name__}' — expected str (base64) or bytes."
        )

    errors: list[str] = []
    for name, fn in [("Fernet", _try_fernet), ("AES-GCM", _try_aesgcm)]:
        try:
            return fn(key_bytes, ciphertext)
        except Exception as exc:
            errors.append(f"{name}: {exc}")

    raise DecryptionError(" | ".join(errors))


# ════════════════════════════════════════════════════════════════════════════
# Field-level result
# ════════════════════════════════════════════════════════════════════════════
def _validate_single_value(
    resolved_path: str,
    value: Any,
    key_bytes: bytes,
) -> dict:
    """Return a field-level result dict for one resolved value."""
    if value is _MISSING:
        return {"path": resolved_path, "status": Status.SKIPPED,
                "reason": "Path not found in document."}

    if value is None:
        return {"path": resolved_path, "status": Status.INVALID,
                "reason": "Value is null."}

    if value in ("", b""):
        return {"path": resolved_path, "status": Status.INVALID,
                "reason": "Value is empty."}

    if not isinstance(value, (str, bytes)):
        return {"path": resolved_path, "status": Status.INVALID,
                "reason": f"Value type '{type(value).__name__}' is not encryptable (expected str/bytes)."}

    try:
        decrypt_value(value, key_bytes)
        return {"path": resolved_path, "status": Status.VALID,
                "reason": "Decryption successful."}
    except DecryptionError as exc:
        return {"path": resolved_path, "status": Status.INVALID,
                "reason": f"Decryption failed: {exc}"}


# ════════════════════════════════════════════════════════════════════════════
# Document validator  (all fields)
# ════════════════════════════════════════════════════════════════════════════
def validate_document(
    doc: dict,
    field_paths: list[str],
    key_bytes: bytes,
) -> dict:
    """
    Validate all *field_paths* in a single document.

    Returns
    -------
    {
        "_id"           : ...,
        "overall_status": "VALID" | "INVALID" | "SKIPPED",
        "fields"        : [
            {
                "field"   : "contacts[].email",
                "results" : [
                    {"path": "contacts[0].email", "status": ..., "reason": ...},
                    {"path": "contacts[1].email", "status": ..., "reason": ...},
                ]
            },
            ...
        ]
    }

    Overall status rules:
      • Any INVALID  → INVALID
      • All SKIPPED  → SKIPPED
      • Otherwise    → VALID
    """
    doc_id = doc.get("_id", "<unknown>")
    field_results: list[dict] = []
    has_invalid = False
    has_valid   = False

    for field_path in field_paths:
        segments = _parse_path(field_path)
        leaf_results: list[dict] = []

        for resolved_path, value in _resolve_values(doc, segments):
            r = _validate_single_value(resolved_path, value, key_bytes)
            leaf_results.append(r)
            if r["status"] == Status.INVALID:
                has_invalid = True
            elif r["status"] == Status.VALID:
                has_valid = True

        field_results.append({"field": field_path, "results": leaf_results})

    if has_invalid:
        overall = Status.INVALID
    elif has_valid:
        overall = Status.VALID
    else:
        overall = Status.SKIPPED

    return {
        "_id":            doc_id,
        "overall_status": overall,
        "fields":         field_results,
    }


# ════════════════════════════════════════════════════════════════════════════
# Collection-level runner
# ════════════════════════════════════════════════════════════════════════════
def run_validation(
    uri: str,
    db_name: str,
    collection_name: str,
    field_paths: list[str],
    key_bytes: bytes,
    query_filter: dict | None = None,
    batch_size: int = 100,
) -> dict:
    log.info("Connecting to MongoDB …")
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
    except ConnectionFailure as exc:
        sys.exit(f"❌  Cannot reach MongoDB: {exc}")

    db  = client[db_name]
    col = db[collection_name]
    query_filter = query_filter or {}
    total = col.count_documents(query_filter)
    log.info(
        "Collection '%s.%s' — %d document(s), validating %d field path(s).",
        db_name, collection_name, total, len(field_paths),
    )

    results: list[dict] = []
    counters: dict[Status, int] = defaultdict(int)

    for doc in col.find(query_filter, batch_size=batch_size):
        result = validate_document(doc, field_paths, key_bytes)
        results.append(result)
        counters[result["overall_status"]] += 1

    client.close()

    return {
        "meta": {
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "uri":              uri,
            "database":         db_name,
            "collection":       collection_name,
            "fields_validated": field_paths,
            "total_documents":  total,
        },
        "counters": {
            "valid":   counters[Status.VALID],
            "invalid": counters[Status.INVALID],
            "skipped": counters[Status.SKIPPED],
        },
        "results": results,
    }


# ════════════════════════════════════════════════════════════════════════════
# Console report
# ════════════════════════════════════════════════════════════════════════════
def print_report(summary: dict) -> None:
    meta = summary["meta"]
    cnt  = summary["counters"]

    W = 70
    print("\n" + "═" * W)
    print("  MongoDB Encrypted Field Validation Report")
    print("═" * W)
    print(f"  Timestamp  : {meta['timestamp']}")
    print(f"  Database   : {meta['database']}")
    print(f"  Collection : {meta['collection']}")
    print(f"  Fields     : {', '.join(meta['fields_validated'])}")
    print(f"  Total docs : {meta['total_documents']}")
    print("─" * W)
    print(f"  ✅  VALID   : {cnt['valid']}")
    print(f"  ❌  INVALID : {cnt['invalid']}")
    print(f"  ⏭️   SKIPPED : {cnt['skipped']}")
    print("═" * W)

    invalid_docs = [r for r in summary["results"] if r["overall_status"] == Status.INVALID]
    if not invalid_docs:
        print("\n  No invalid documents found. 🎉\n")
        return

    print(f"\n  ── Invalid Documents ({len(invalid_docs)}) ──\n")
    for doc_r in invalid_docs:
        print(f"  _id: {doc_r['_id']}")
        for field_r in doc_r["fields"]:
            bad = [r for r in field_r["results"] if r["status"] == Status.INVALID]
            for r in bad:
                print(f"    ❌  {r['path']}")
                print(f"        {r['reason']}")
        print()


# ════════════════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════════════════
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Validate multiple encrypted fields in MongoDB documents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--uri",          default="mongodb://localhost:27017")
    p.add_argument("--db",           required=True)
    p.add_argument("--collection",   required=True)
    p.add_argument("--key",          required=True,
                   help="Base64-encoded Fernet or AES-256 key")
    p.add_argument("--fields",       nargs="+", metavar="PATH",
                   help="One or more field paths. Use [] for arrays. E.g: ssn personal.dob contacts[].phone")
    p.add_argument("--fields-config", metavar="FILE",
                   help="JSON file containing a list of field paths")
    p.add_argument("--filter",       default="{}", metavar="JSON")
    p.add_argument("--batch-size",   type=int, default=100)
    p.add_argument("--output",       default=None, metavar="FILE")
    p.add_argument("--log-level",    default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)

    # ── Collect field paths ──────────────────────────────────────────────────
    field_paths: list[str] = []
    if args.fields:
        field_paths.extend(args.fields)
    if args.fields_config:
        try:
            with open(args.fields_config) as f:
                extra = json.load(f)
            if not isinstance(extra, list):
                sys.exit("❌  --fields-config must be a JSON array of strings.")
            field_paths.extend(extra)
        except (OSError, json.JSONDecodeError) as exc:
            sys.exit(f"❌  Cannot read --fields-config: {exc}")

    if not field_paths:
        sys.exit("❌  Provide at least one field via --fields or --fields-config.")

    # Deduplicate preserving order
    seen: set[str] = set()
    field_paths = [p for p in field_paths if not (p in seen or seen.add(p))]  # type: ignore[func-returns-value]

    # ── Decode key ───────────────────────────────────────────────────────────
    try:
        key_bytes = base64.urlsafe_b64decode(args.key)
    except Exception:
        try:
            key_bytes = base64.b64decode(args.key)
        except Exception as exc:
            sys.exit(f"❌  Invalid --key: {exc}")

    # ── Parse filter ─────────────────────────────────────────────────────────
    try:
        query_filter = json.loads(args.filter)
    except json.JSONDecodeError as exc:
        sys.exit(f"❌  Invalid --filter JSON: {exc}")

    # ── Run ──────────────────────────────────────────────────────────────────
    summary = run_validation(
        uri=args.uri,
        db_name=args.db,
        collection_name=args.collection,
        field_paths=field_paths,
        key_bytes=key_bytes,
        query_filter=query_filter,
        batch_size=args.batch_size,
    )

    print_report(summary)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, default=str)
        log.info("Results written to '%s'.", args.output)

    if summary["counters"]["invalid"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
