"""
config.py — Central configuration for the KYC/AML Automation Workflow.

Every tunable value (thresholds, model names, risk weights, file paths) lives
here so that compliance officers can review and change policy in ONE place
without touching business logic. Values can be overridden with environment
variables (see .env.example).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("KYC_DATA_DIR", BASE_DIR / "data"))
REPORTS_DIR = Path(os.getenv("KYC_REPORTS_DIR", BASE_DIR / "reports"))
DB_PATH = Path(os.getenv("KYC_DB_PATH", DATA_DIR / "kyc_aml.db"))
SANCTIONS_LIST_PATH = Path(os.getenv("KYC_SANCTIONS_LIST", BASE_DIR / "sanctions_list_mock.json"))
SAMPLE_DOCS_DIR = BASE_DIR / "sample_kyc_documents"

DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------- #
# Claude API
# --------------------------------------------------------------------------- #
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
# Model is configurable — check https://docs.claude.com/en/docs/about-claude/models
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-5")
CLAUDE_MAX_TOKENS = int(os.getenv("CLAUDE_MAX_TOKENS", "2048"))
CLAUDE_TIMEOUT_SECONDS = float(os.getenv("CLAUDE_TIMEOUT_SECONDS", "60"))
CLAUDE_MAX_RETRIES = int(os.getenv("CLAUDE_MAX_RETRIES", "3"))

# "auto"    -> use Claude when an API key is present, otherwise offline fallback
# "claude"  -> require Claude (fail if no key)
# "offline" -> never call Claude (deterministic; used by the test suite)
AI_MODE = os.getenv("KYC_AI_MODE", "auto").lower()


def claude_enabled() -> bool:
    """Return True if the pipeline should call the Claude API."""
    if AI_MODE == "offline":
        return False
    if AI_MODE == "claude" and not ANTHROPIC_API_KEY:
        raise RuntimeError("KYC_AI_MODE=claude but ANTHROPIC_API_KEY is not set")
    return bool(ANTHROPIC_API_KEY)


# --------------------------------------------------------------------------- #
# Sanctions screening thresholds (0.0 – 1.0 similarity)
# --------------------------------------------------------------------------- #
# >= MATCH_THRESHOLD           -> "MATCH"            (auto-escalate, block onboarding)
# >= POTENTIAL_MATCH_THRESHOLD -> "POTENTIAL_MATCH"  (human review required)
# below                        -> "NO_MATCH"
SANCTIONS_MATCH_THRESHOLD = float(os.getenv("SANCTIONS_MATCH_THRESHOLD", "0.90"))
SANCTIONS_POTENTIAL_MATCH_THRESHOLD = float(os.getenv("SANCTIONS_POTENTIAL_THRESHOLD", "0.80"))

# --------------------------------------------------------------------------- #
# Risk model
# --------------------------------------------------------------------------- #
# Score bands (0–100). Policy: >= HIGH -> High, >= MEDIUM -> Medium, else Low.
RISK_BAND_HIGH = 60
RISK_BAND_MEDIUM = 30

# FATF lists as published after the June 2026 plenary. They change three times
# a year — in production, load them from a maintained data feed and re-review
# after every FATF plenary (Feb / Jun / Oct).
# https://www.fatf-gafi.org/en/topics/high-risk-and-other-monitored-jurisdictions.html
FATF_LIST_AS_OF = "2026-06"
FATF_CALL_FOR_ACTION = {"IR", "KP", "MM"}  # "black list": Iran, DPRK, Myanmar
FATF_INCREASED_MONITORING = {               # "grey list"
    "AO", "BO", "BA", "BG", "CM", "CI", "CD", "HT", "IQ", "KE", "KW",
    "LA", "LB", "MC", "NP", "PG", "SS", "SY", "VE", "VN", "VG", "YE",
}

# Occupation / business-type risk (keyword -> points). Lower-cased match.
OCCUPATION_RISK = {
    "money exchange": 25, "money service": 25, "remittance": 25, "hawala": 30,
    "currency exchange": 25, "precious metals": 20, "gold": 20, "jewel": 20,
    "real estate": 15, "car dealer": 15, "used car": 15, "casino": 30,
    "crypto": 25, "virtual asset": 25, "arms": 30, "defence contractor": 20,
    "cash-intensive": 15, "import/export": 10, "trading company": 10,
    "charity": 15, "non-profit": 15, "shell": 25,
}

LOGGING_LEVEL = os.getenv("KYC_LOG_LEVEL", "INFO").upper()


def get_logger(name: str) -> logging.Logger:
    """Consistent structured-ish logging across all modules."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(LOGGING_LEVEL)
    logger.propagate = False
    return logger
