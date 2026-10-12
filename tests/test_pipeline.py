"""
Test suite for the KYC/AML pipeline.

    pytest -v                 # offline, deterministic (default)

Scenarios come from test_cases.json so business users can add cases without
touching Python.
"""

from __future__ import annotations

import io
import json
import sqlite3
from pathlib import Path

import pytest

import config
from aml_sanctions_checker import name_similarity, normalise_name, screen_customer
from compliance_report_generator import build_report, decide
from database_handler import canonical_json, sha256_text
from kyc_document_parser import ParserError, normalise_and_validate, parse_document
from main import process_document
from risk_classifier import classify_risk

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "sample_kyc_documents"
CASES = json.loads((ROOT / "test_cases.json").read_text(encoding="utf-8"))


def _abs(p: str) -> Path:
    """Report paths are stored relative to the project root when inside it."""
    path = Path(p)
    return path if path.is_absolute() else config.BASE_DIR / path


# --------------------------------------------------------------------------- #
# 1. Sanctions screening
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("case", CASES["screening_cases"], ids=lambda c: c["id"])
def test_screening_scenarios(case):
    result = screen_customer(**case["input"])
    assert result["status"] == case["expected_status"], f"{case['why']}: {result['explanation']}"


def test_transliteration_normalisation():
    assert normalise_name("Mohamed Abdalla El-Rashidi") == normalise_name("Muhammad Abdullah Al Rashidi")
    assert normalise_name("Abd al-Rahman") == normalise_name("Abdulrahman")
    assert normalise_name("Alexander Smith") == ["alexander", "smith"]  # western 'al' kept


def test_name_similarity_is_order_independent():
    assert name_similarity("Rashidi Mohammed", "Mohammed Rashidi") == 1.0


def test_false_positive_records_adjustments():
    r = screen_customer("Faisal Omar Al-Nimri", "SA", "1990-07-02")
    m = r["matches"][0]
    assert m["name_score"] == 1.0 and m["final_score"] < config.SANCTIONS_POTENTIAL_MATCH_THRESHOLD
    assert any("birth year differs" in a for a in m["adjustments"])
    assert "false positive" in r["explanation"]


def test_screening_requires_name():
    with pytest.raises(ValueError):
        screen_customer("  ")


# --------------------------------------------------------------------------- #
# 2. Document parsing & validation
# --------------------------------------------------------------------------- #
def test_parse_clean_pdf_offline():
    out = parse_document(DOCS / "01_clean_customer.pdf", use_claude=False)
    d, m = out["data"], out["metadata"]
    assert d["full_name"] == "Sara Abdulaziz Al-Mansour"
    assert d["nationality"] == "SA"                  # "Saudi Arabia" -> ISO
    assert d["date_of_birth"] == "1992-04-18"        # DD/MM/YYYY -> ISO
    assert d["monthly_income_sar"] == 22000.0        # "22,000" -> number
    assert d["pep_status"] is False
    assert m["missing_fields"] == [] and m["validation_issues"] == []
    assert len(m["document_sha256"]) == 64


def test_validation_flags_bad_saudi_id_and_expiry():
    data, issues = normalise_and_validate({
        "full_name": "X", "id_type": "National ID", "id_number": "3123", "nationality": "SA",
        "date_of_birth": "01/01/1990", "id_expiry_date": "2020-01-01"})
    assert any("not a valid 10-digit" in i for i in issues)
    assert any("EXPIRED" in i for i in issues)


def test_parser_rejects_unsupported_and_empty(tmp_path):
    bad = tmp_path / "doc.txt"
    bad.write_text("hello")
    with pytest.raises(ParserError):
        parse_document(bad, use_claude=False)
    empty = tmp_path / "empty.pdf"
    empty.write_bytes(b"")
    with pytest.raises(ParserError):
        parse_document(empty, use_claude=False)


def test_offline_mode_refuses_images():
    with pytest.raises(ParserError, match="Offline mode"):
        parse_document(DOCS / "06_scanned_id_card.png", use_claude=False)


# --------------------------------------------------------------------------- #
# 3. Risk classification
# --------------------------------------------------------------------------- #
def _extraction(**overrides):
    data = {"full_name": "Test Person", "nationality": "SA", "occupation": "Teacher",
            "monthly_income_sar": 10000, "expected_monthly_volume_sar": 8000,
            "source_of_funds": "Salary", "pep_status": False}
    data.update(overrides)
    return {"data": data, "metadata": {"missing_fields": [], "validation_issues": [], "confidence": 1.0}}


CLEAR = {"status": "NO_MATCH", "top_score": 0.0, "matches": [], "explanation": "clear"}


def test_low_risk_baseline():
    r = classify_risk(_extraction(), CLEAR, use_claude=False)
    assert r["risk_level"] == "Low" and r["due_diligence"] == "SDD" and not r["requires_manual_review"]


@pytest.mark.parametrize("override,rule", [
    ({"pep_status": True}, "PEP"),
    ({"nationality": "KP"}, "FATF_BLACKLIST"),
])
def test_hard_stops_force_high(override, rule):
    r = classify_risk(_extraction(**override), CLEAR, use_claude=False)
    assert r["risk_level"] == "High"
    assert rule in {h["rule"] for h in r["hard_stops"]}


def test_ai_cannot_downgrade_rules(monkeypatch):
    """Claude says Low on a sanctions MATCH -> rule floor (High) must stand."""
    import risk_classifier
    screening = screen_customer("Mohammed Abdullah Al-Rashidi", "YE", "1978-03-14")
    monkeypatch.setattr(risk_classifier, "call_structured", lambda *a, **k: {
        "result": {"risk_level": "Low", "reasoning": "looks fine", "key_risk_factors": [],
                   "recommended_actions": [], "confidence": 0.9}, "model": "mock", "usage": {}, "latency_ms": 1})
    r = classify_risk(_extraction(), screening, use_claude=True)
    assert r["risk_level"] == "High" and r["ai_level"] == "Low"
    assert "cannot downgrade" in r["ai_disagreement"]


def test_ai_escalation_requires_human(monkeypatch):
    """Claude escalates a rules-Low customer -> High, flagged for human confirmation."""
    import risk_classifier
    monkeypatch.setattr(risk_classifier, "call_structured", lambda *a, **k: {
        "result": {"risk_level": "High", "reasoning": "pattern X", "key_risk_factors": ["X"],
                   "recommended_actions": ["EDD"], "confidence": 0.8}, "model": "mock", "usage": {}, "latency_ms": 1})
    r = classify_risk(_extraction(), CLEAR, use_claude=True)
    assert r["risk_level"] == "High" and r["rule_based_level"] == "Low"
    assert r["requires_manual_review"]
    assert any("AI escalated" in x for x in r["review_reasons"])


def test_claude_failure_falls_back_to_rules(monkeypatch):
    import risk_classifier
    from claude_client import ClaudeError

    def boom(*a, **k):
        raise ClaudeError("timeout")
    monkeypatch.setattr(risk_classifier, "call_structured", boom)
    r = classify_risk(_extraction(), CLEAR, use_claude=True)
    assert r["method"] == "rules" and r["ai_error"] == "timeout" and r["requires_manual_review"]


# --------------------------------------------------------------------------- #
# 4. End-to-end document scenarios
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("case", CASES["document_cases"], ids=lambda c: c["id"])
def test_document_scenarios_end_to_end(case, db):
    if case.get("requires_claude") and not config.claude_enabled():
        pytest.skip("requires Claude vision (set ANTHROPIC_API_KEY and KYC_AI_MODE=auto)")
    s = process_document(DOCS / case["document"], db)
    exp = case["expected"]
    if "sanctions_status" in exp:
        assert s["sanctions_status"] == exp["sanctions_status"]
    if "sanctions_status_in" in exp:
        assert s["sanctions_status"] in exp["sanctions_status_in"]
    if "risk_level" in exp:
        assert s["risk_level"] == exp["risk_level"], s["review_reasons"]
    if "risk_level_in" in exp:
        assert s["risk_level"] in exp["risk_level_in"]
    assert s["requires_manual_review"] == exp["requires_manual_review"]
    if "decision" in exp:
        report = json.loads(_abs(s["json_report"]).read_text())
        assert report["decision"]["code"] == exp["decision"]

    bundle = db.get_case_bundle(s["case_id"])
    assert bundle["case"]["status"] == "COMPLETED"
    actions = [e["action"] for e in bundle["audit_trail"]]
    assert actions[0] == "CASE_CREATED" and actions[-1] == "STATUS_COMPLETED"
    for stage in ("STATUS_EXTRACTED", "STATUS_SCREENED", "STATUS_CLASSIFIED"):
        assert stage in actions
    if exp["requires_manual_review"]:
        assert "ESCALATED_FOR_REVIEW" in actions


# --------------------------------------------------------------------------- #
# 5. Audit trail integrity
# --------------------------------------------------------------------------- #
def test_audit_log_is_append_only(db):
    case_id = db.create_case("x.pdf", "abc")
    with sqlite3.connect(db.db_path) as conn:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("UPDATE audit_log SET action='HACKED' WHERE case_id=?", (case_id,))
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM audit_log")


def test_audit_chain_detects_tampering(db):
    case_id = db.create_case("x.pdf", "abc")
    db.log_audit(case_id, "tester", "SOMETHING", {"a": 1})
    db.log_audit(case_id, "tester", "SOMETHING_ELSE", {"b": 2})
    assert db.verify_audit_chain()["valid"]
    # An attacker with raw DB access drops the trigger and edits history
    with sqlite3.connect(db.db_path) as conn:
        conn.execute("DROP TRIGGER audit_log_no_update")
        conn.execute("UPDATE audit_log SET details_json='{\"a\": 999}' WHERE action='SOMETHING'")
    v = db.verify_audit_chain()
    assert not v["valid"] and v["broken_at"] == 2


# --------------------------------------------------------------------------- #
# 6. Report
# --------------------------------------------------------------------------- #
def test_report_hash_and_decision(db):
    s = process_document(DOCS / "02_flagged_sanctions_match.pdf", db)
    bundle = db.get_case_bundle(s["case_id"])
    rep = build_report(bundle)
    recomputed = sha256_text(canonical_json({k: v for k, v in rep.items() if k != "integrity"}))
    assert rep["integrity"]["report_sha256"] == recomputed
    assert rep["decision"]["code"] == "BLOCK"
    assert rep["customer"]["id_number_masked"].endswith("3478") and "*" in rep["customer"]["id_number_masked"]
    pdf = _abs(s["pdf_report"])
    assert pdf.exists() and pdf.read_bytes()[:4] == b"%PDF"


def test_decide_matrix():
    assert decide({"status": "MATCH"}, {"risk_level": "High"}) == "BLOCK"
    assert decide({"status": "NO_MATCH"}, {"risk_level": "Low", "requires_manual_review": False}) == "AUTO_APPROVE"
    assert decide({"status": "NO_MATCH"}, {"risk_level": "Medium", "requires_manual_review": False}) == "APPROVE_CDD"
    assert decide({"status": "NO_MATCH"}, {"risk_level": "Low", "requires_manual_review": True}) == "REFER"
    assert decide(None, None) == "REFER"


# --------------------------------------------------------------------------- #
# 7. REST API (the contract n8n relies on)
# --------------------------------------------------------------------------- #
@pytest.fixture()
def client():
    import api_server
    api_server.app.config["TESTING"] = True
    return api_server.app.test_client()


def _upload(client, path: Path, url="/api/v1/parse"):
    return client.post(url, data={"document": (io.BytesIO(path.read_bytes()), path.name)},
                       content_type="multipart/form-data")


def test_api_stage_by_stage_flow(client):
    r = _upload(client, DOCS / "03_high_risk_pep_msb.pdf")
    assert r.status_code == 200, r.json
    case_id = r.json["case_id"]
    for stage in ("screen", "classify"):
        r = client.post(f"/api/v1/{stage}", json={"case_id": case_id})
        assert r.status_code == 200, r.json
    assert r.json["risk_level"] == "High"
    r = client.post("/api/v1/report", json={"case_id": case_id})
    assert r.status_code == 200 and r.json["decision"]["code"] == "REFER"
    r = client.post("/api/v1/escalate", json={"case_id": case_id, "priority": "P2", "reason": "test"})
    assert r.status_code == 200 and r.json["review_id"] > 0
    assert client.get(f"/api/v1/reports/{case_id}.pdf").status_code == 200
    assert client.get("/api/v1/audit/verify").json["valid"]


def test_api_one_shot_process(client):
    r = _upload(client, DOCS / "01_clean_customer.pdf", "/api/v1/process")
    assert r.status_code == 200 and r.json["risk_level"] == "Low"


def test_api_errors(client):
    assert client.post("/api/v1/parse", data={}, content_type="multipart/form-data").status_code == 400
    r = client.post("/api/v1/parse", data={"document": (io.BytesIO(b"x"), "a.exe")},
                    content_type="multipart/form-data")
    assert r.status_code == 415
    r = client.post("/api/v1/screen", json={"case_id": "KYC-NOPE"})
    assert r.status_code == 404 and r.json["error"]["code"] == "CASE_NOT_FOUND"
    assert client.post("/api/v1/screen", json={}).status_code == 400
    # Image in offline mode -> extraction fails cleanly, case marked FAILED
    r = _upload(client, DOCS / "06_scanned_id_card.png")
    assert r.status_code == 422 and r.json["error"]["code"] == "EXTRACTION_FAILED"
    assert client.get(f"/api/v1/cases/{r.json['case_id']}").json["case"]["status"] == "FAILED"


def test_api_key_enforced(client, monkeypatch):
    import api_server
    monkeypatch.setattr(api_server, "API_KEY", "secret")
    assert client.get("/api/v1/cases").status_code == 401
    assert client.get("/api/v1/cases", headers={"X-API-Key": "secret"}).status_code == 200
