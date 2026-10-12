"""
risk_classifier.py — Stage 3: classify customer AML risk as Low / Medium / High.

Input : extraction result (from kyc_document_parser) + screening result
        (from aml_sanctions_checker)
Output: JSON dict
        {
          "risk_level": "Low"|"Medium"|"High", "risk_score": 0-100,
          "factors": [ {category, factor, points, detail} ],
          "hard_stops": [...], "reasoning": str,
          "due_diligence": "SDD"|"CDD"|"EDD",
          "requires_manual_review": bool, "review_reasons": [...],
          "recommended_actions": [...], "method": "rules"|"rules+claude", ...
        }

Design: "rules decide the floor, AI adds judgement"
---------------------------------------------------
1. A transparent, weighted RULE ENGINE scores the customer across the classic
   risk dimensions — customer, geography, product/activity, screening, and
   data quality. Some conditions are HARD STOPS that force High regardless
   of score (confirmed sanctions match, PEP, FATF call-for-action country).
2. CLAUDE then reviews the full profile and the rule factors, and returns its
   own level with written reasoning and recommended actions.
3. The final level is max(rule level, Claude level). Claude can ESCALATE but
   can never DOWNGRADE a rule-based decision, and any AI escalation is routed
   to a human analyst. This keeps the model explainable and auditable — a
   regulator can always trace the minimum outcome to deterministic rules.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from typing import Any

import config
from claude_client import ClaudeError, call_structured

logger = config.get_logger("risk_classifier")

LEVELS = ["Low", "Medium", "High"]
REVIEW_CYCLE_YEARS = {"Low": 3, "Medium": 2, "High": 1}
VAGUE_SOURCES = {"cash", "other", "gift", "gifts", "savings", "family", "unknown", "personal"}

RISK_SCHEMA = {
    "type": "object",
    "properties": {
        "risk_level": {"type": "string", "enum": LEVELS},
        "reasoning": {"type": "string", "description": "3-6 sentences an auditor can follow"},
        "key_risk_factors": {"type": "array", "items": {"type": "string"}},
        "mitigating_factors": {"type": "array", "items": {"type": "string"}},
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number", "description": "0-1"},
    },
    "required": ["risk_level", "reasoning", "key_risk_factors", "recommended_actions", "confidence"],
}

SYSTEM_PROMPT = """You are a senior AML compliance analyst at a Saudi bank applying SAMA's
risk-based approach (aligned with FATF Recommendations). You receive a customer profile, a
sanctions screening result and the output of the bank's rule-based risk engine. Assess the
customer's money-laundering / terrorist-financing risk as Low, Medium or High.
- Consider customer type, occupation, geography, expected activity versus declared income,
  source of funds, PEP status, screening results and data quality.
- You may conclude a HIGHER level than the rule engine if you see a risk it missed; explain why.
- Never ignore a rule-engine hard stop.
- Be concise, factual and specific; no generic boilerplate."""


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def classify_risk(extraction: dict, screening: dict, use_claude: bool | None = None) -> dict:
    """Classify risk for one customer. Main entry point."""
    use_claude = config.claude_enabled() if use_claude is None else use_claude
    data = extraction.get("data", extraction)
    meta = extraction.get("metadata", {})

    factors, hard_stops, review_reasons = _rule_engine(data, meta, screening)
    score = min(100, sum(f["points"] for f in factors))
    rule_level = _band(score)
    for hs in hard_stops:
        rule_level = _max_level(rule_level, hs["floor"])
    if any(hs["floor"] == "High" for hs in hard_stops):
        score = max(score, config.RISK_BAND_HIGH)

    result: dict[str, Any] = {
        "rule_based_level": rule_level,
        "risk_score": score,
        "factors": factors,
        "hard_stops": hard_stops,
        "ai_level": None,
        "method": "rules",
        "model": None,
    }

    final_level = rule_level
    if use_claude:
        try:
            ai = _claude_assessment(data, meta, screening, factors, hard_stops, rule_level, score)
            ai_level = ai["result"]["risk_level"]
            result.update({
                "ai_level": ai_level,
                "ai_confidence": ai["result"].get("confidence"),
                "method": "rules+claude",
                "model": ai["model"],
                "reasoning": ai["result"]["reasoning"],
                "key_risk_factors": ai["result"].get("key_risk_factors", []),
                "mitigating_factors": ai["result"].get("mitigating_factors", []),
                "recommended_actions": ai["result"].get("recommended_actions", []),
            })
            if LEVELS.index(ai_level) > LEVELS.index(rule_level):
                final_level = ai_level
                review_reasons.append(f"AI escalated risk from {rule_level} to {ai_level} — human confirmation required")
            elif LEVELS.index(ai_level) < LEVELS.index(rule_level):
                result["ai_disagreement"] = (f"AI suggested {ai_level}; rule floor {rule_level} retained "
                                             "(AI cannot downgrade rule-based decisions)")
        except ClaudeError as exc:
            logger.warning("Claude unavailable, falling back to rules only: %s", exc)
            result["ai_error"] = str(exc)
            review_reasons.append("AI review unavailable — rules-only decision")

    if "reasoning" not in result:
        result["reasoning"] = _rule_reasoning(final_level, score, factors, hard_stops)
        result["key_risk_factors"] = [f"{f['factor']} (+{f['points']})" for f in factors if f["points"] > 0]
        result["recommended_actions"] = _default_actions(final_level, screening, hard_stops)

    if final_level == "High":
        review_reasons.append("High-risk customer — EDD and senior management approval required")
    result.update({
        "risk_level": final_level,
        "due_diligence": {"Low": "SDD", "Medium": "CDD", "High": "EDD"}[final_level],
        "requires_manual_review": bool(review_reasons),
        "review_reasons": list(dict.fromkeys(review_reasons)),
        "next_review_date": (date.today() + timedelta(days=365 * REVIEW_CYCLE_YEARS[final_level])).isoformat(),
        "classified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    logger.info("Risk %s (score %d, method %s)", final_level, score, result["method"])
    return result


# --------------------------------------------------------------------------- #
# Rule engine
# --------------------------------------------------------------------------- #
def _rule_engine(d: dict, meta: dict, s: dict) -> tuple[list[dict], list[dict], list[str]]:
    factors: list[dict] = []
    hard: list[dict] = []
    review: list[str] = []

    def add(category: str, factor: str, points: int, detail: str = "") -> None:
        factors.append({"category": category, "factor": factor, "points": points, "detail": detail})

    # 1. Screening ----------------------------------------------------------
    status = s.get("status", "NO_MATCH")
    if status == "MATCH":
        top = s["matches"][0]
        add("screening", "Sanctions list MATCH", 60,
            f"{top['matched_name']} / {top['list']} {top['uid']} (score {top['final_score']:.2f})")
        hard.append({"rule": "SANCTIONS_MATCH", "floor": "High",
                     "detail": "Confirmed-level sanctions match — onboarding blocked pending MLRO decision"})
        review.append("Sanctions MATCH — MLRO escalation required")
    elif status == "POTENTIAL_MATCH":
        top = s["matches"][0]
        add("screening", "Sanctions POTENTIAL match", 35,
            f"{top['matched_name']} / {top['uid']} (score {top['final_score']:.2f})")
        review.append("Potential sanctions match — analyst must confirm or discount")
    else:
        add("screening", "Sanctions screening clear", 0, s.get("explanation", ""))

    # 2. Customer -----------------------------------------------------------
    if d.get("pep_status"):
        add("customer", "Politically Exposed Person", 30, d.get("pep_details") or "Declared PEP")
        hard.append({"rule": "PEP", "floor": "High",
                     "detail": "PEP — EDD, source-of-wealth check and senior management approval required"})

    occ = " ".join(filter(None, [d.get("occupation"), d.get("business_type"), d.get("employer")])).lower()
    occ_hits = [(k, v) for k, v in config.OCCUPATION_RISK.items() if k in occ]
    if occ_hits:
        k, v = max(occ_hits, key=lambda kv: kv[1])
        add("activity", "High-risk occupation / business type", v, f"matched '{k}' in '{occ}'")

    # 3. Geography ----------------------------------------------------------
    for field in ("nationality", "country_of_residence"):
        c = (d.get(field) or "").upper()
        if c in config.FATF_CALL_FOR_ACTION:
            add("geography", f"{field} in FATF call-for-action jurisdiction", 40, c)
            hard.append({"rule": "FATF_BLACKLIST", "floor": "High",
                         "detail": f"{field} {c} on FATF call-for-action list"})
        elif c in config.FATF_INCREASED_MONITORING:
            add("geography", f"{field} in FATF increased-monitoring jurisdiction", 20, c)

    # 4. Expected activity vs profile --------------------------------------
    income = d.get("monthly_income_sar")
    volume = d.get("expected_monthly_volume_sar")
    if volume:
        if income:
            ratio = volume / income if income else 0
            if ratio > 10:
                add("activity", "Expected volume far exceeds income", 25, f"{ratio:.1f}x declared income")
            elif ratio > 3:
                add("activity", "Expected volume exceeds income", 15, f"{ratio:.1f}x declared income")
        else:
            add("activity", "Expected volume with no declared income", 10, f"SAR {volume:,.0f}/month")
        if volume >= 500_000:
            add("activity", "High absolute transaction volume", 10, f"SAR {volume:,.0f}/month")

    sof = (d.get("source_of_funds") or "").strip().lower()
    if not sof:
        add("customer", "Source of funds not declared", 10)
    elif sof in VAGUE_SOURCES:
        add("customer", "Vague source of funds", 10, f"'{sof}'")

    # 5. Data quality -------------------------------------------------------
    missing = meta.get("missing_fields", [])
    if missing:
        add("data_quality", "Missing required KYC fields", min(20, 5 * len(missing)), ", ".join(missing))
        review.append(f"Incomplete KYC: {', '.join(missing)}")
    issues = meta.get("validation_issues", [])
    if any("EXPIRED" in i for i in issues):
        add("data_quality", "Identity document expired", 15)
        review.append("Expired ID — obtain valid document before onboarding")
    other = [i for i in issues if "EXPIRED" not in i]
    if other:
        add("data_quality", "Document validation issues", min(15, 5 * len(other)), "; ".join(other))
        review.append("Validation issues: " + "; ".join(other))
    if any("under 18" in i for i in issues):
        review.append("Customer is a minor — guardian account rules apply")
    conf = meta.get("confidence")
    if isinstance(conf, (int, float)) and conf < 0.7:
        review.append(f"Low extraction confidence ({conf:.2f})")
    if meta.get("extraction_notes"):
        review.append(f"Extractor notes: {meta['extraction_notes']}")

    return factors, hard, review


def _band(score: int) -> str:
    if score >= config.RISK_BAND_HIGH:
        return "High"
    if score >= config.RISK_BAND_MEDIUM:
        return "Medium"
    return "Low"


def _max_level(a: str, b: str) -> str:
    return a if LEVELS.index(a) >= LEVELS.index(b) else b


# --------------------------------------------------------------------------- #
# Claude layer
# --------------------------------------------------------------------------- #
def _claude_assessment(d, meta, s, factors, hard, rule_level, score) -> dict:
    profile = {k: v for k, v in d.items() if k not in ("phone", "email", "id_number")}  # data minimisation
    payload = {
        "customer_profile": profile,
        "document_checks": {"missing_fields": meta.get("missing_fields"),
                            "validation_issues": meta.get("validation_issues"),
                            "extraction_confidence": meta.get("confidence")},
        "sanctions_screening": {"status": s.get("status"), "top_score": s.get("top_score"),
                                "explanation": s.get("explanation"),
                                "matches": s.get("matches", [])[:3]},
        "rule_engine": {"level": rule_level, "score": score, "factors": factors, "hard_stops": hard},
    }
    content = [{"type": "text", "text":
                "Assess this customer and call record_risk_assessment.\n\n" +
                json.dumps(payload, indent=2, ensure_ascii=False, default=str)}]
    return call_structured(SYSTEM_PROMPT, content, "record_risk_assessment",
                           "Record the AML risk assessment for the customer.", RISK_SCHEMA)


# --------------------------------------------------------------------------- #
# Offline reasoning
# --------------------------------------------------------------------------- #
def _rule_reasoning(level: str, score: int, factors: list[dict], hard: list[dict]) -> str:
    drivers = sorted((f for f in factors if f["points"] > 0), key=lambda f: -f["points"])
    parts = [f"Rule engine assigned {level} risk with a score of {score}/100."]
    if hard:
        parts.append("Hard-stop rules applied: " + "; ".join(h["detail"] for h in hard) + ".")
    if drivers:
        parts.append("Main drivers: " + "; ".join(
            f"{f['factor']} (+{f['points']}{', ' + f['detail'] if f['detail'] else ''})" for f in drivers[:4]) + ".")
    else:
        parts.append("No risk indicators were triggered: screening clear, standard occupation, "
                     "non-high-risk geography, activity consistent with declared income.")
    return " ".join(parts)


def _default_actions(level: str, s: dict, hard: list[dict]) -> list[str]:
    rules = {h["rule"] for h in hard}
    actions = []
    if "SANCTIONS_MATCH" in rules:
        actions += ["Block onboarding and freeze any pending transactions",
                    "Escalate to MLRO within 24 hours",
                    "If confirmed, report to the Saudi FIU (SAFIU) and apply targeted financial sanctions"]
    elif s.get("status") == "POTENTIAL_MATCH":
        actions.append("Analyst to compare full identifiers (DOB, ID, photo) against the listed entry")
    if "PEP" in rules:
        actions += ["Obtain senior management approval", "Verify source of wealth and source of funds"]
    if level == "High":
        actions += ["Apply Enhanced Due Diligence (EDD)", "Enhanced ongoing transaction monitoring",
                    "Annual KYC refresh"]
    elif level == "Medium":
        actions += ["Standard CDD with documentary verification of income/source of funds",
                    "KYC refresh every 2 years"]
    else:
        actions += ["Proceed with standard onboarding", "KYC refresh every 3 years"]
    return actions


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Classify risk from saved extraction + screening JSON")
    p.add_argument("extraction_json")
    p.add_argument("screening_json")
    p.add_argument("--offline", action="store_true")
    a = p.parse_args()
    with open(a.extraction_json) as f1, open(a.screening_json) as f2:
        print(json.dumps(classify_risk(json.load(f1), json.load(f2),
                                       use_claude=False if a.offline else None), indent=2))
