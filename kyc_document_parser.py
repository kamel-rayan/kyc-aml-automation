"""
kyc_document_parser.py — Stage 1: extract structured customer data from a KYC document.

Input : path to a PDF or image (PNG/JPG/WEBP) — e.g. a customer onboarding
        form, a national ID / Iqama scan, a passport page.
Output: JSON dict
        {
          "data":     { full_name, id_number, nationality, date_of_birth, ... },
          "metadata": { method, model, confidence, missing_fields,
                        validation_issues, document_sha256, ... }
        }

Extraction engines
------------------
1. Claude (primary) — the document is sent natively (PDF document block or
   image block). Claude returns the fields through a forced tool call, so the
   output is always schema-valid JSON.
2. Offline text parser (fallback) — for text-based PDFs only, reads
   "Label: value" lines with pdfplumber. Lets the demo and test suite run
   without an API key; it is NOT meant for real scanned documents.

After extraction, every record goes through the same deterministic
validation layer (date formats, ISO country codes, Saudi ID format, document
expiry, required fields). AI output is never trusted blindly.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import config
from claude_client import ClaudeError, call_structured, file_to_content_block
from database_handler import sha256_file

logger = config.get_logger("kyc_parser")

SUPPORTED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".webp"}
MAX_FILE_BYTES = 20 * 1024 * 1024  # 20 MB

REQUIRED_FIELDS = ["full_name", "id_number", "nationality", "date_of_birth",
                   "id_expiry_date", "occupation"]

# JSON schema Claude must fill. Also documents the canonical record format.
EXTRACTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "full_name": {"type": ["string", "null"], "description": "Full legal name in Latin script"},
        "full_name_arabic": {"type": ["string", "null"], "description": "Name in Arabic script if present"},
        "id_type": {"type": ["string", "null"],
                    "enum": ["NATIONAL_ID", "IQAMA", "PASSPORT", "COMMERCIAL_REGISTRATION", "OTHER", None]},
        "id_number": {"type": ["string", "null"]},
        "nationality": {"type": ["string", "null"], "description": "ISO 3166-1 alpha-2 code, e.g. SA"},
        "date_of_birth": {"type": ["string", "null"], "description": "YYYY-MM-DD (convert Hijri to Gregorian)"},
        "gender": {"type": ["string", "null"], "enum": ["M", "F", None]},
        "id_issue_date": {"type": ["string", "null"], "description": "YYYY-MM-DD"},
        "id_expiry_date": {"type": ["string", "null"], "description": "YYYY-MM-DD"},
        "occupation": {"type": ["string", "null"]},
        "employer": {"type": ["string", "null"]},
        "business_type": {"type": ["string", "null"], "description": "Nature of business if self-employed / company"},
        "address": {"type": ["string", "null"]},
        "city": {"type": ["string", "null"]},
        "country_of_residence": {"type": ["string", "null"], "description": "ISO alpha-2"},
        "phone": {"type": ["string", "null"]},
        "email": {"type": ["string", "null"]},
        "monthly_income_sar": {"type": ["number", "null"]},
        "expected_monthly_volume_sar": {"type": ["number", "null"]},
        "source_of_funds": {"type": ["string", "null"]},
        "purpose_of_account": {"type": ["string", "null"]},
        "pep_status": {"type": ["boolean", "null"], "description": "Politically Exposed Person declared?"},
        "pep_details": {"type": ["string", "null"]},
        "confidence": {"type": "number", "description": "0-1 overall extraction confidence"},
        "extraction_notes": {"type": ["string", "null"],
                             "description": "Illegible fields, signs of tampering, inconsistencies"},
    },
    "required": ["full_name", "id_number", "nationality", "date_of_birth", "confidence"],
}

SYSTEM_PROMPT = """You are a KYC document-extraction engine for a Saudi bank's compliance team.
Extract ONLY what is printed on the document. Never guess or invent values; use null when a
field is absent or illegible. Normalise dates to YYYY-MM-DD (convert Hijri dates to Gregorian),
countries to ISO 3166-1 alpha-2, and money to plain numbers in SAR. Saudi National IDs start
with 1, Iqama (resident) numbers start with 2; both are 10 digits. Report anything suspicious
(mismatched fonts, altered dates, inconsistent data) in extraction_notes."""

# Country names -> ISO alpha-2 (subset; extend as needed)
COUNTRY_CODES = {
    "saudi arabia": "SA", "saudi": "SA", "ksa": "SA", "united arab emirates": "AE", "uae": "AE",
    "kuwait": "KW", "qatar": "QA", "bahrain": "BH", "oman": "OM", "yemen": "YE", "egypt": "EG",
    "jordan": "JO", "syria": "SY", "lebanon": "LB", "iraq": "IQ", "iran": "IR", "turkey": "TR",
    "turkiye": "TR", "pakistan": "PK", "india": "IN", "bangladesh": "BD", "philippines": "PH",
    "indonesia": "ID", "sudan": "SD", "south sudan": "SS", "somalia": "SO", "afghanistan": "AF",
    "united kingdom": "GB", "uk": "GB", "united states": "US", "usa": "US", "russia": "RU",
    "north korea": "KP", "myanmar": "MM", "venezuela": "VE", "haiti": "HT", "morocco": "MA",
    "tunisia": "TN", "algeria": "DZ", "libya": "LY", "nigeria": "NG", "ethiopia": "ET",
}

# Offline parser label map: label on the form -> canonical field
LABEL_MAP = {
    "full name": "full_name", "name": "full_name", "name (arabic)": "full_name_arabic",
    "id type": "id_type", "id number": "id_number", "national id": "id_number",
    "iqama number": "id_number", "passport number": "id_number",
    "nationality": "nationality", "date of birth": "date_of_birth", "gender": "gender",
    "id issue date": "id_issue_date", "id expiry date": "id_expiry_date", "expiry date": "id_expiry_date",
    "occupation": "occupation", "employer": "employer", "business type": "business_type",
    "nature of business": "business_type", "address": "address", "city": "city",
    "country of residence": "country_of_residence", "phone": "phone", "email": "email",
    "monthly income (sar)": "monthly_income_sar",
    "expected monthly transactions (sar)": "expected_monthly_volume_sar",
    "source of funds": "source_of_funds", "purpose of account": "purpose_of_account",
    "politically exposed person": "pep_status", "pep details": "pep_details",
}


class ParserError(Exception):
    """Raised when a document cannot be processed."""


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def parse_document(file_path: str | Path, use_claude: bool | None = None) -> dict:
    """Extract and validate KYC data from a document. Main entry point."""
    path = Path(file_path)
    _check_file(path)
    use_claude = config.claude_enabled() if use_claude is None else use_claude
    doc_type = "pdf" if path.suffix.lower() == ".pdf" else "image"
    logger.info("Parsing %s (%s) via %s", path.name, doc_type, "claude" if use_claude else "offline")

    meta: dict[str, Any] = {
        "source_file": path.name,
        "document_type": doc_type,
        "document_sha256": sha256_file(path),
        "processed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    if use_claude:
        raw, call_meta = _extract_with_claude(path)
        meta.update({"method": "claude", **call_meta})
    else:
        if doc_type != "pdf":
            raise ParserError("Offline mode supports text-based PDFs only. "
                              "Set ANTHROPIC_API_KEY to process images/scans with Claude.")
        raw = _extract_offline(path)
        meta.update({"method": "offline_text", "model": None})

    data, issues = normalise_and_validate(raw)
    missing = [f for f in REQUIRED_FIELDS if not data.get(f)]
    ai_conf = raw.get("confidence")
    completeness = 1 - len(missing) / len(REQUIRED_FIELDS)
    confidence = round(min(ai_conf, completeness) if isinstance(ai_conf, (int, float)) else completeness, 2)

    meta.update({
        "confidence": confidence,
        "missing_fields": missing,
        "validation_issues": issues,
        "extraction_notes": raw.get("extraction_notes"),
    })
    return {"data": data, "metadata": meta}


# --------------------------------------------------------------------------- #
# Engines
# --------------------------------------------------------------------------- #
def _extract_with_claude(path: Path) -> tuple[dict, dict]:
    content = [
        file_to_content_block(path),
        {"type": "text", "text": "Extract the KYC fields from this document using the record_kyc_data tool."},
    ]
    try:
        resp = call_structured(
            system=SYSTEM_PROMPT, content=content, tool_name="record_kyc_data",
            tool_description="Record the structured KYC fields extracted from the document.",
            input_schema=EXTRACTION_SCHEMA)
    except ClaudeError as exc:
        raise ParserError(str(exc)) from exc
    return resp["result"], {"model": resp["model"], "usage": resp["usage"],
                            "latency_ms": resp["latency_ms"]}


def _extract_offline(path: Path) -> dict:
    try:
        import pdfplumber
    except ImportError as exc:  # pragma: no cover
        raise ParserError("pdfplumber is required for offline mode") from exc
    with pdfplumber.open(path) as pdf:
        text = "\n".join((page.extract_text() or "") for page in pdf.pages)
    if not text.strip():
        raise ParserError("No text layer found (scanned image?). Use Claude mode.")

    raw: dict[str, Any] = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z][A-Za-z ()/]+?)\s*:\s*(.+?)\s*$", line)
        if not m:
            continue
        key = LABEL_MAP.get(m.group(1).strip().lower())
        if key and key not in raw:
            raw[key] = m.group(2).strip()
    return raw


# --------------------------------------------------------------------------- #
# Validation & normalisation (deterministic — applies to BOTH engines)
# --------------------------------------------------------------------------- #
def normalise_and_validate(raw: dict) -> tuple[dict, list[str]]:
    issues: list[str] = []
    data: dict[str, Any] = {k: raw.get(k) for k in EXTRACTION_SCHEMA["properties"]
                            if k not in ("confidence", "extraction_notes")}
    for k, v in list(data.items()):
        if isinstance(v, str):
            v = v.strip()
            data[k] = None if v.lower() in ("", "n/a", "na", "none", "null", "-") else v

    for k in ("nationality", "country_of_residence"):
        if data.get(k):
            code = to_iso_country(data[k])
            if code is None:
                issues.append(f"{k}: unrecognised country '{data[k]}'")
            data[k] = code or data[k]

    for k in ("date_of_birth", "id_issue_date", "id_expiry_date"):
        if data.get(k):
            parsed = parse_date(data[k])
            if parsed is None:
                issues.append(f"{k}: unparseable date '{data[k]}'")
            else:
                data[k] = parsed.isoformat()

    for k in ("monthly_income_sar", "expected_monthly_volume_sar"):
        if data.get(k) is not None and not isinstance(data[k], (int, float)):
            num = re.sub(r"[^\d.]", "", str(data[k]))
            data[k] = float(num) if num else None

    if isinstance(data.get("pep_status"), str):
        data["pep_status"] = data["pep_status"].strip().lower() in ("yes", "y", "true", "1")

    if data.get("id_type"):
        data["id_type"] = str(data["id_type"]).upper().replace(" ", "_")
    if data.get("id_number"):
        data["id_number"] = re.sub(r"\s", "", str(data["id_number"]))
        issues += validate_saudi_id(data["id_number"], data.get("id_type"), data.get("nationality"))

    today = date.today()
    if data.get("id_expiry_date") and parse_date(data["id_expiry_date"]):
        if parse_date(data["id_expiry_date"]) < today:
            issues.append(f"id_expiry_date: document EXPIRED on {data['id_expiry_date']}")
    if data.get("date_of_birth") and parse_date(data["date_of_birth"]):
        dob = parse_date(data["date_of_birth"])
        age = (today - dob).days // 365
        if age < 18:
            issues.append(f"date_of_birth: customer is under 18 (age {age})")
        if age > 110:
            issues.append(f"date_of_birth: implausible age {age}")
    return data, issues


def validate_saudi_id(id_number: str, id_type: str | None, nationality: str | None) -> list[str]:
    """Format checks for Saudi National ID (starts 1) and Iqama (starts 2).
    Production systems should additionally verify against Absher/Yakeen (via
    an approved integration such as Elm) rather than rely on format alone."""
    issues = []
    if id_type in ("NATIONAL_ID", "IQAMA") or (nationality == "SA" and id_type != "PASSPORT"):
        if not re.fullmatch(r"[12]\d{9}", id_number):
            issues.append(f"id_number: '{id_number}' is not a valid 10-digit Saudi ID/Iqama format")
        elif id_type == "NATIONAL_ID" and id_number[0] != "1":
            issues.append("id_number: National ID should start with 1")
        elif id_type == "IQAMA" and id_number[0] != "2":
            issues.append("id_number: Iqama should start with 2")
    return issues


def to_iso_country(value: str) -> str | None:
    v = value.strip()
    if re.fullmatch(r"[A-Za-z]{2}", v):
        return v.upper()
    return COUNTRY_CODES.get(v.lower())


def parse_date(value: str) -> date | None:
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%d %B %Y", "%d %b %Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(str(value).strip(), fmt).date()
        except ValueError:
            continue
    return None


def _check_file(path: Path) -> None:
    if not path.exists():
        raise ParserError(f"File not found: {path}")
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ParserError(f"Unsupported file type '{path.suffix}'. Allowed: {sorted(SUPPORTED_EXTENSIONS)}")
    size = path.stat().st_size
    if size == 0:
        raise ParserError("File is empty")
    if size > MAX_FILE_BYTES:
        raise ParserError(f"File too large ({size} bytes > {MAX_FILE_BYTES})")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Extract KYC data from a document")
    p.add_argument("file")
    p.add_argument("--offline", action="store_true", help="Force offline text parser")
    a = p.parse_args()
    print(json.dumps(parse_document(a.file, use_claude=False if a.offline else None),
                     indent=2, ensure_ascii=False))
