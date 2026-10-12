"""
api_server.py — REST API that exposes each pipeline stage to n8n (or any client).

n8n's HTTP Request nodes call these endpoints in sequence. Each stage reads
its inputs from the database by `case_id`, so n8n only has to pass the case id
along — the system of record stays in one place and every call is audited.

    python api_server.py                 # http://0.0.0.0:8000
    KYC_API_PORT=9000 python api_server.py

Endpoints (all JSON unless noted)
---------------------------------
GET  /health                          liveness + config summary
POST /api/v1/parse      multipart     field "document" (PDF/image) -> case_id + extraction
POST /api/v1/screen     {case_id}     sanctions screening
POST /api/v1/classify   {case_id}     risk classification
POST /api/v1/report     {case_id}     JSON+PDF report, case -> COMPLETED
POST /api/v1/escalate   {case_id, priority?, reason?}   add to manual review queue
POST /api/v1/audit      {case_id?, action, details?}    write an audit event (n8n error branch)
POST /api/v1/process    multipart     one-shot: full pipeline in a single call
POST /api/v1/screen/name {name, nationality?, date_of_birth?}  ad-hoc screening (no case)
GET  /api/v1/cases                    recent cases
GET  /api/v1/cases/<case_id>          full case bundle incl. audit trail
GET  /api/v1/reports/<case_id>.pdf    download PDF report
GET  /api/v1/reviews                  open manual-review queue
GET  /api/v1/audit/verify             verify the audit hash chain

Security: if KYC_API_KEY is set, every /api/* call must send header
"X-API-Key: <value>". In production put this behind TLS + mTLS/OAuth2.
"""

from __future__ import annotations

import os
import uuid
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, send_file
from werkzeug.utils import secure_filename

import config
from aml_sanctions_checker import screen_customer
from compliance_report_generator import generate_report
from database_handler import DatabaseHandler, sha256_file
from kyc_document_parser import SUPPORTED_EXTENSIONS, ParserError, parse_document
from main import process_document
from risk_classifier import classify_risk

logger = config.get_logger("api")
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
UPLOAD_DIR = config.DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
db = DatabaseHandler()
API_KEY = os.getenv("KYC_API_KEY", "")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
class APIError(Exception):
    def __init__(self, status: int, code: str, message: str, case_id: str | None = None):
        super().__init__(message)
        self.status, self.code, self.message, self.case_id = status, code, message, case_id


@app.errorhandler(APIError)
def _api_error(e: APIError):
    return jsonify({"success": False, "case_id": e.case_id,
                    "error": {"code": e.code, "message": e.message}}), e.status


@app.errorhandler(413)
def _too_large(_e):
    return jsonify({"success": False, "error": {"code": "FILE_TOO_LARGE", "message": "Max 20 MB"}}), 413


@app.errorhandler(Exception)
def _unhandled(e: Exception):
    logger.exception("Unhandled error")
    return jsonify({"success": False, "error": {"code": "INTERNAL_ERROR", "message": str(e)}}), 500


def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if API_KEY and request.headers.get("X-API-Key") != API_KEY:
            raise APIError(401, "UNAUTHORIZED", "Missing or invalid X-API-Key")
        return fn(*args, **kwargs)
    return wrapper


def _case_id_from_body() -> str:
    body = request.get_json(silent=True) or {}
    case_id = body.get("case_id")
    if not case_id:
        raise APIError(400, "MISSING_CASE_ID", "JSON body must include case_id")
    if not db.case_exists(case_id):
        raise APIError(404, "CASE_NOT_FOUND", f"Unknown case_id {case_id}", case_id)
    return case_id


def _save_upload() -> Path:
    f = request.files.get("document") or request.files.get("file") or request.files.get("data")
    if f is None and request.files:
        f = next(iter(request.files.values()))
    if f is None or not f.filename:
        raise APIError(400, "NO_FILE", "Upload a file in multipart field 'document'")
    name = secure_filename(f.filename)
    if Path(name).suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise APIError(415, "UNSUPPORTED_TYPE", f"Allowed: {sorted(SUPPORTED_EXTENSIONS)}")
    dest = UPLOAD_DIR / f"{uuid.uuid4().hex[:8]}_{name}"
    f.save(dest)
    return dest


def _fail(case_id: str, stage: str, exc: Exception, status: int = 422, code: str = "STAGE_FAILED"):
    db.update_case_status(case_id, "FAILED", stage, {"error": str(exc), "type": type(exc).__name__})
    raise APIError(status, code, f"{stage}: {exc}", case_id)


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/health")
def health():
    return jsonify({"status": "ok", "ai_mode": "claude" if config.claude_enabled() else "offline",
                    "model": config.CLAUDE_MODEL if config.claude_enabled() else None,
                    "database": str(db.db_path)})


@app.post("/api/v1/parse")
@require_api_key
def parse():
    path = _save_upload()
    case_id = db.create_case(path.name, sha256_file(path), request.form.get("channel", "n8n"))
    try:
        extraction = parse_document(path)
    except ParserError as exc:
        _fail(case_id, "kyc_document_parser", exc, 422, "EXTRACTION_FAILED")
    db.save_extraction(case_id, extraction)
    return jsonify({"success": True, "case_id": case_id, "stage": "extraction", "extraction": extraction})


@app.post("/api/v1/screen")
@require_api_key
def screen():
    case_id = _case_id_from_body()
    ext = db.get_case_bundle(case_id)["extraction"]
    if not ext or not ext["data"].get("full_name"):
        _fail(case_id, "aml_sanctions_checker", ValueError("no extracted customer name"), 409, "NOT_READY")
    d = ext["data"]
    try:
        result = screen_customer(d["full_name"], d.get("nationality"), d.get("date_of_birth"))
    except Exception as exc:
        _fail(case_id, "aml_sanctions_checker", exc, 500)
    db.save_screening(case_id, result)
    return jsonify({"success": True, "case_id": case_id, "stage": "screening", "screening": result})


@app.post("/api/v1/classify")
@require_api_key
def classify():
    case_id = _case_id_from_body()
    b = db.get_case_bundle(case_id)
    if not b["extraction"] or not b["screening"]:
        raise APIError(409, "NOT_READY", "Run /parse and /screen first", case_id)
    try:
        risk = classify_risk(b["extraction"], b["screening"])
    except Exception as exc:
        _fail(case_id, "risk_classifier", exc, 500)
    db.save_risk_assessment(case_id, risk)
    return jsonify({"success": True, "case_id": case_id, "stage": "risk", "risk": risk,
                    "risk_level": risk["risk_level"],
                    "requires_manual_review": risk["requires_manual_review"]})


@app.post("/api/v1/report")
@require_api_key
def report():
    case_id = _case_id_from_body()
    b = db.get_case_bundle(case_id)
    if not b["risk"]:
        raise APIError(409, "NOT_READY", "Run /classify first", case_id)
    try:
        rep = generate_report(b, audit_chain=db.verify_audit_chain())
    except Exception as exc:
        _fail(case_id, "compliance_report_generator", exc, 500)
    db.save_report(case_id, rep["json_path"], rep["pdf_path"], rep["report_sha256"])
    r = rep["report"]
    return jsonify({
        "success": True, "case_id": case_id, "stage": "report",
        "decision": r["decision"],
        "risk_level": r["risk_assessment"]["risk_level"],
        "risk_score": r["risk_assessment"]["risk_score"],
        "sanctions_status": r["sanctions_screening"]["status"],
        "requires_manual_review": r["risk_assessment"]["requires_manual_review"],
        "review_reasons": r["risk_assessment"]["review_reasons"],
        "report_sha256": rep["report_sha256"],
        "pdf_url": f"/api/v1/reports/{case_id}.pdf" if rep["pdf_path"] else None,
        "report": r,
    })


@app.post("/api/v1/escalate")
@require_api_key
def escalate():
    case_id = _case_id_from_body()
    body = request.get_json(silent=True) or {}
    priority = body.get("priority", "P2")
    if priority not in ("P1", "P2", "P3"):
        raise APIError(400, "BAD_PRIORITY", "priority must be P1, P2 or P3", case_id)
    review_id = db.enqueue_review(case_id, priority, str(body.get("reason", "Escalated by workflow"))[:500])
    return jsonify({"success": True, "case_id": case_id, "review_id": review_id, "priority": priority})


@app.post("/api/v1/audit")
@require_api_key
def audit():
    body = request.get_json(silent=True) or {}
    if not body.get("action"):
        raise APIError(400, "MISSING_ACTION", "action is required")
    case_id = body.get("case_id")
    if case_id and not db.case_exists(case_id):
        case_id = None
    h = db.log_audit(case_id, body.get("actor", "n8n"), str(body["action"])[:100], body.get("details") or {})
    return jsonify({"success": True, "entry_hash": h})


@app.post("/api/v1/process")
@require_api_key
def process():
    path = _save_upload()
    try:
        summary = process_document(path, db, source_channel="api")
    except ParserError as exc:
        raise APIError(422, "EXTRACTION_FAILED", str(exc))
    return jsonify({"success": True, **summary,
                    "pdf_url": f"/api/v1/reports/{summary['case_id']}.pdf"})


@app.post("/api/v1/screen/name")
@require_api_key
def screen_name():
    body = request.get_json(silent=True) or {}
    if not body.get("name"):
        raise APIError(400, "MISSING_NAME", "name is required")
    return jsonify(screen_customer(body["name"], body.get("nationality"), body.get("date_of_birth")))


@app.get("/api/v1/cases")
@require_api_key
def cases():
    return jsonify(db.list_cases(int(request.args.get("limit", 50))))


@app.get("/api/v1/cases/<case_id>")
@require_api_key
def case(case_id: str):
    try:
        return jsonify(db.get_case_bundle(case_id))
    except KeyError:
        raise APIError(404, "CASE_NOT_FOUND", f"Unknown case_id {case_id}", case_id)


@app.get("/api/v1/reports/<case_id>.pdf")
@require_api_key
def report_pdf(case_id: str):
    pdf = config.REPORTS_DIR / f"{secure_filename(case_id)}.pdf"
    if not pdf.exists():
        raise APIError(404, "REPORT_NOT_FOUND", "No PDF for this case", case_id)
    return send_file(pdf, mimetype="application/pdf", download_name=pdf.name)


@app.get("/api/v1/reviews")
@require_api_key
def reviews():
    return jsonify(db.open_reviews())


@app.get("/api/v1/audit/verify")
@require_api_key
def verify():
    return jsonify(db.verify_audit_chain())


if __name__ == "__main__":
    port = int(os.getenv("KYC_API_PORT", "8000"))
    logger.info("KYC/AML API on :%d (AI mode: %s)", port, "claude" if config.claude_enabled() else "offline")
    app.run(host="0.0.0.0", port=port, threaded=True)
