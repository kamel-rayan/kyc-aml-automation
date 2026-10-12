"""
main.py — End-to-end demo / CLI for the KYC/AML pipeline.

    python main.py                                   # process the default sample
    python main.py sample_kyc_documents/02_flagged_sanctions_match.pdf
    python main.py --all                             # process every sample document
    python main.py --all --offline                   # no Claude calls (deterministic)

Runs the same five stages the n8n workflow orchestrates:

    Document -> [1] Extract -> [2] Sanctions screen -> [3] Risk classify
             -> [4] Report (JSON + PDF) -> [5] Persist + audit trail

`process_document()` is also imported by api_server.py for the one-shot
/api/v1/process endpoint, so the CLI and the API share one code path.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import config
from aml_sanctions_checker import screen_customer
from compliance_report_generator import generate_report
from database_handler import DatabaseHandler, sha256_file
from kyc_document_parser import ParserError, parse_document
from risk_classifier import classify_risk

logger = config.get_logger("main")
DEFAULT_SAMPLE = config.SAMPLE_DOCS_DIR / "01_clean_customer.pdf"


def process_document(file_path: str | Path, db: DatabaseHandler | None = None,
                     use_claude: bool | None = None, source_channel: str = "cli",
                     case_id: str | None = None) -> dict:
    """Run the full pipeline for one document and return a summary dict."""
    db = db or DatabaseHandler()
    path = Path(file_path)
    case_id = case_id or db.create_case(path.name, sha256_file(path) if path.exists() else None, source_channel)

    try:
        extraction = parse_document(path, use_claude=use_claude)
        db.save_extraction(case_id, extraction)

        d = extraction["data"]
        if not d.get("full_name"):
            raise ParserError("No customer name could be extracted — cannot screen")
        screening = screen_customer(d["full_name"], d.get("nationality"), d.get("date_of_birth"))
        db.save_screening(case_id, screening)

        risk = classify_risk(extraction, screening, use_claude=use_claude)
        db.save_risk_assessment(case_id, risk)

        if risk["requires_manual_review"]:
            priority = "P1" if screening["status"] == "MATCH" else ("P2" if risk["risk_level"] == "High" else "P3")
            db.enqueue_review(case_id, priority, "; ".join(risk["review_reasons"])[:500])

        bundle = db.get_case_bundle(case_id)
        rep = generate_report(bundle, audit_chain=db.verify_audit_chain())
        db.save_report(case_id, rep["json_path"], rep["pdf_path"], rep["report_sha256"])
    except Exception as exc:
        logger.error("Case %s failed: %s", case_id, exc)
        db.update_case_status(case_id, "FAILED", "pipeline", {"error": str(exc), "type": type(exc).__name__})
        raise

    return {
        "case_id": case_id,
        "customer": d.get("full_name"),
        "decision": rep["report"]["decision"]["label"],
        "risk_level": risk["risk_level"],
        "risk_score": risk["risk_score"],
        "sanctions_status": screening["status"],
        "requires_manual_review": risk["requires_manual_review"],
        "review_reasons": risk["review_reasons"],
        "json_report": rep["json_path"],
        "pdf_report": rep["pdf_path"],
        "report_sha256": rep["report_sha256"],
        "method": risk["method"],
    }


def _print_summary(s: dict) -> None:
    bar = "=" * 72
    print(f"\n{bar}\n {s['case_id']}  |  {s['customer']}\n{bar}")
    print(f" Decision        : {s['decision']}")
    print(f" Risk            : {s['risk_level']} ({s['risk_score']}/100) via {s['method']}")
    print(f" Sanctions       : {s['sanctions_status']}")
    if s["review_reasons"]:
        print(" Review reasons  :")
        for r in s["review_reasons"]:
            print(f"   - {r}")
    print(f" Reports         : {s['json_report']}\n                   {s['pdf_report']}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="KYC/AML end-to-end demo")
    p.add_argument("document", nargs="?", help="PDF/image to process (default: clean sample)")
    p.add_argument("--all", action="store_true", help="Process every file in sample_kyc_documents/")
    p.add_argument("--offline", action="store_true", help="Do not call Claude (rules + text parser only)")
    p.add_argument("--json", action="store_true", help="Print machine-readable JSON summary")
    a = p.parse_args(argv)

    use_claude = False if a.offline else None
    if a.all:
        exts = {".pdf"} if (a.offline or not config.claude_enabled()) else {".pdf", ".png", ".jpg", ".jpeg"}
        docs = sorted(f for f in config.SAMPLE_DOCS_DIR.iterdir() if f.suffix.lower() in exts)
    else:
        docs = [Path(a.document) if a.document else DEFAULT_SAMPLE]

    mode = "Claude + rules" if (use_claude is None and config.claude_enabled()) else "OFFLINE (rules + text parser)"
    print(f"KYC/AML pipeline — mode: {mode} — {len(docs)} document(s)")
    db = DatabaseHandler()
    results, failures = [], 0
    for doc in docs:
        try:
            s = process_document(doc, db, use_claude=use_claude)
            results.append(s)
            if not a.json:
                _print_summary(s)
        except Exception as exc:
            failures += 1
            print(f"\n[FAILED] {doc.name}: {exc}", file=sys.stderr)

    chain = db.verify_audit_chain()
    if a.json:
        print(json.dumps({"results": results, "audit_chain": chain}, indent=2))
    else:
        print(f"\nAudit chain: {'VALID' if chain['valid'] else 'BROKEN at ' + str(chain['broken_at'])} "
              f"({chain['entries']} entries). Database: {db.db_path}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
