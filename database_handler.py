"""
database_handler.py — SQLite persistence layer with a tamper-evident audit trail.

Responsibilities
----------------
* Store every KYC case and the output of each pipeline stage
  (extraction, sanctions screening, risk assessment, report).
* Keep an APPEND-ONLY audit log. Each entry carries the SHA-256 hash of the
  previous entry (a hash chain), and SQLite triggers reject UPDATE/DELETE on
  the table. Any tampering breaks the chain and is detected by
  `verify_audit_chain()`.
* Maintain a manual-review queue for cases that need a human analyst.

SQLite is used for the proof-of-concept. The schema is deliberately plain SQL
so it ports to PostgreSQL / Oracle (typical in Saudi banks) with minimal change.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import config

logger = config.get_logger("database")

GENESIS_HASH = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS kyc_cases (
    case_id            TEXT PRIMARY KEY,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    status             TEXT NOT NULL,      -- RECEIVED|EXTRACTED|SCREENED|CLASSIFIED|COMPLETED|FAILED
    document_filename  TEXT,
    document_sha256    TEXT,
    source_channel     TEXT DEFAULT 'api'
);

CREATE TABLE IF NOT EXISTS customer_records (
    case_id        TEXT PRIMARY KEY REFERENCES kyc_cases(case_id),
    full_name      TEXT,
    id_number      TEXT,
    id_type        TEXT,
    nationality    TEXT,
    date_of_birth  TEXT,
    id_expiry_date TEXT,
    occupation     TEXT,
    employer       TEXT,
    address        TEXT,
    extraction_method TEXT,
    extraction_confidence REAL,
    extracted_json TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS screening_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       TEXT NOT NULL REFERENCES kyc_cases(case_id),
    status        TEXT NOT NULL,           -- MATCH|POTENTIAL_MATCH|NO_MATCH
    top_score     REAL NOT NULL,
    lists_checked TEXT NOT NULL,
    result_json   TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_assessments (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id                TEXT NOT NULL REFERENCES kyc_cases(case_id),
    risk_level             TEXT NOT NULL,  -- Low|Medium|High
    risk_score             INTEGER NOT NULL,
    requires_manual_review INTEGER NOT NULL,
    method                 TEXT NOT NULL,  -- rules|rules+claude
    result_json            TEXT NOT NULL,
    created_at             TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS compliance_reports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       TEXT NOT NULL REFERENCES kyc_cases(case_id),
    json_path     TEXT,
    pdf_path      TEXT,
    report_sha256 TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS review_queue (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL REFERENCES kyc_cases(case_id),
    priority    TEXT NOT NULL,             -- P1|P2|P3
    reason      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'OPEN',
    assigned_to TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id      TEXT,
    timestamp    TEXT NOT NULL,
    actor        TEXT NOT NULL,            -- system component or user id
    action       TEXT NOT NULL,
    details_json TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    entry_hash   TEXT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_log(case_id);
CREATE INDEX IF NOT EXISTS idx_screen_case ON screening_results(case_id);
CREATE INDEX IF NOT EXISTS idx_risk_case ON risk_assessments(case_id);

-- Append-only enforcement: the audit trail can never be edited or deleted.
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical_json(obj: Any) -> str:
    """Deterministic JSON (sorted keys) so hashes are reproducible."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class DatabaseHandler:
    """Thin, explicit data-access layer. One short-lived connection per call
    keeps it safe to use from the multi-threaded Flask API."""

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path or config.DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    # ------------------------------------------------------------------ #
    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
        finally:
            conn.close()

    def init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------------ #
    # Audit trail
    # ------------------------------------------------------------------ #
    def log_audit(self, case_id: str | None, actor: str, action: str,
                  details: dict | None = None) -> str:
        """Append a hash-chained audit entry. Returns the entry hash."""
        details = details or {}
        with self._conn() as conn:
            # BEGIN IMMEDIATE serialises writers so the chain never forks.
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
                prev_hash = row["entry_hash"] if row else GENESIS_HASH
                ts = utc_now()
                details_json = canonical_json(details)
                entry_hash = sha256_text(
                    f"{prev_hash}|{case_id}|{ts}|{actor}|{action}|{details_json}")
                conn.execute(
                    "INSERT INTO audit_log (case_id, timestamp, actor, action, details_json,"
                    " prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?)",
                    (case_id, ts, actor, action, details_json, prev_hash, entry_hash))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return entry_hash

    def get_audit_trail(self, case_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, case_id, timestamp, actor, action, details_json, prev_hash, entry_hash"
                " FROM audit_log WHERE case_id = ? ORDER BY id", (case_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d.pop("details_json"))
            out.append(d)
        return out

    def verify_audit_chain(self) -> dict:
        """Recompute every hash. Returns {'valid': bool, 'entries': n, 'broken_at': id|None}."""
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        prev = GENESIS_HASH
        for r in rows:
            expected = sha256_text(
                f"{prev}|{r['case_id']}|{r['timestamp']}|{r['actor']}|{r['action']}|{r['details_json']}")
            if r["prev_hash"] != prev or r["entry_hash"] != expected:
                return {"valid": False, "entries": len(rows), "broken_at": r["id"]}
            prev = r["entry_hash"]
        return {"valid": True, "entries": len(rows), "broken_at": None}

    # ------------------------------------------------------------------ #
    # Cases
    # ------------------------------------------------------------------ #
    def create_case(self, document_filename: str | None, document_sha256: str | None,
                    source_channel: str = "api", case_id: str | None = None) -> str:
        case_id = case_id or f"KYC-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"
        now = utc_now()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO kyc_cases (case_id, created_at, updated_at, status, document_filename,"
                " document_sha256, source_channel) VALUES (?,?,?,?,?,?,?)",
                (case_id, now, now, "RECEIVED", document_filename, document_sha256, source_channel))
        self.log_audit(case_id, "database_handler", "CASE_CREATED", {
            "document_filename": document_filename, "document_sha256": document_sha256,
            "source_channel": source_channel})
        return case_id

    def case_exists(self, case_id: str) -> bool:
        with self._conn() as conn:
            return conn.execute("SELECT 1 FROM kyc_cases WHERE case_id=?",
                                (case_id,)).fetchone() is not None

    def update_case_status(self, case_id: str, status: str, actor: str = "system",
                           details: dict | None = None) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE kyc_cases SET status=?, updated_at=? WHERE case_id=?",
                         (status, utc_now(), case_id))
        self.log_audit(case_id, actor, f"STATUS_{status}", details or {})

    # ------------------------------------------------------------------ #
    # Stage outputs
    # ------------------------------------------------------------------ #
    def save_extraction(self, case_id: str, extraction: dict) -> None:
        data = extraction.get("data", {})
        meta = extraction.get("metadata", {})
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO customer_records (case_id, full_name, id_number, id_type,"
                " nationality, date_of_birth, id_expiry_date, occupation, employer, address,"
                " extraction_method, extraction_confidence, extracted_json, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (case_id, data.get("full_name"), data.get("id_number"), data.get("id_type"),
                 data.get("nationality"), data.get("date_of_birth"), data.get("id_expiry_date"),
                 data.get("occupation"), data.get("employer"), data.get("address"),
                 meta.get("method"), meta.get("confidence"), canonical_json(extraction), utc_now()))
        self.update_case_status(case_id, "EXTRACTED", "kyc_document_parser", {
            "method": meta.get("method"), "confidence": meta.get("confidence"),
            "missing_fields": meta.get("missing_fields", []),
            "output_sha256": sha256_text(canonical_json(extraction))})

    def save_screening(self, case_id: str, screening: dict) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO screening_results (case_id, status, top_score, lists_checked,"
                " result_json, created_at) VALUES (?,?,?,?,?,?)",
                (case_id, screening["status"], screening["top_score"],
                 ",".join(screening.get("lists_checked", [])), canonical_json(screening), utc_now()))
        self.update_case_status(case_id, "SCREENED", "aml_sanctions_checker", {
            "status": screening["status"], "top_score": screening["top_score"],
            "matches": len(screening.get("matches", [])),
            "list_version": screening.get("list_version"),
            "output_sha256": sha256_text(canonical_json(screening))})

    def save_risk_assessment(self, case_id: str, risk: dict) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO risk_assessments (case_id, risk_level, risk_score,"
                " requires_manual_review, method, result_json, created_at) VALUES (?,?,?,?,?,?,?)",
                (case_id, risk["risk_level"], risk["risk_score"],
                 int(risk["requires_manual_review"]), risk["method"], canonical_json(risk), utc_now()))
        self.update_case_status(case_id, "CLASSIFIED", "risk_classifier", {
            "risk_level": risk["risk_level"], "risk_score": risk["risk_score"],
            "method": risk["method"],
            "output_sha256": sha256_text(canonical_json(risk))})

    def save_report(self, case_id: str, json_path: str | None, pdf_path: str | None,
                    report_sha256: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO compliance_reports (case_id, json_path, pdf_path, report_sha256,"
                " created_at) VALUES (?,?,?,?,?)",
                (case_id, json_path, pdf_path, report_sha256, utc_now()))
        self.update_case_status(case_id, "COMPLETED", "compliance_report_generator", {
            "json_path": json_path, "pdf_path": pdf_path, "report_sha256": report_sha256})

    def enqueue_review(self, case_id: str, priority: str, reason: str) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO review_queue (case_id, priority, reason, created_at) VALUES (?,?,?,?)",
                (case_id, priority, reason, utc_now()))
            review_id = cur.lastrowid
        self.log_audit(case_id, "workflow", "ESCALATED_FOR_REVIEW",
                       {"review_id": review_id, "priority": priority, "reason": reason})
        return review_id

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #
    def get_case_bundle(self, case_id: str) -> dict:
        """Everything known about a case — used by the report generator."""
        with self._conn() as conn:
            case = conn.execute("SELECT * FROM kyc_cases WHERE case_id=?", (case_id,)).fetchone()
            if case is None:
                raise KeyError(f"Unknown case_id: {case_id}")
            cust = conn.execute("SELECT extracted_json FROM customer_records WHERE case_id=?",
                                (case_id,)).fetchone()
            scr = conn.execute("SELECT result_json FROM screening_results WHERE case_id=?"
                               " ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
            risk = conn.execute("SELECT result_json FROM risk_assessments WHERE case_id=?"
                                " ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
        return {
            "case": dict(case),
            "extraction": json.loads(cust["extracted_json"]) if cust else None,
            "screening": json.loads(scr["result_json"]) if scr else None,
            "risk": json.loads(risk["result_json"]) if risk else None,
            "audit_trail": self.get_audit_trail(case_id),
        }

    def list_cases(self, limit: int = 50) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT c.case_id, c.created_at, c.status, r.full_name,"
                " (SELECT risk_level FROM risk_assessments ra WHERE ra.case_id=c.case_id"
                "  ORDER BY ra.id DESC LIMIT 1) AS risk_level"
                " FROM kyc_cases c LEFT JOIN customer_records r ON r.case_id=c.case_id"
                " ORDER BY c.created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def open_reviews(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM review_queue WHERE status='OPEN'"
                                " ORDER BY priority, created_at").fetchall()
        return [dict(r) for r in rows]


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="KYC/AML database utilities")
    p.add_argument("command", choices=["init", "list", "verify", "reviews", "case"])
    p.add_argument("--case-id")
    a = p.parse_args()
    db = DatabaseHandler()
    if a.command == "init":
        print(f"Schema ready at {db.db_path}")
    elif a.command == "list":
        print(json.dumps(db.list_cases(), indent=2))
    elif a.command == "verify":
        print(json.dumps(db.verify_audit_chain(), indent=2))
    elif a.command == "reviews":
        print(json.dumps(db.open_reviews(), indent=2))
    elif a.command == "case":
        print(json.dumps(db.get_case_bundle(a.case_id), indent=2, ensure_ascii=False))
