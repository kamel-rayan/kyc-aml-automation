"""Test configuration: isolated temp DB/reports and OFFLINE mode (no Claude calls,
fully deterministic). Environment must be set BEFORE project modules import config."""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_tmp = Path(tempfile.mkdtemp(prefix="kyc_tests_"))
os.environ["KYC_AI_MODE"] = "offline"
os.environ["KYC_DATA_DIR"] = str(_tmp / "data")
os.environ["KYC_DB_PATH"] = str(_tmp / "data" / "test.db")
os.environ["KYC_REPORTS_DIR"] = str(_tmp / "reports")
os.environ["KYC_LOG_LEVEL"] = "WARNING"
os.environ.pop("KYC_API_KEY", None)

import json  # noqa: E402

import pytest  # noqa: E402


@pytest.fixture(scope="session")
def test_cases():
    return json.loads((ROOT / "test_cases.json").read_text(encoding="utf-8"))


@pytest.fixture()
def db(tmp_path):
    from database_handler import DatabaseHandler
    return DatabaseHandler(tmp_path / "kyc.db")


@pytest.fixture(scope="session", autouse=True)
def sample_docs():
    """Make sure sample documents exist (regenerate if missing)."""
    docs = ROOT / "sample_kyc_documents"
    if not (docs / "01_clean_customer.pdf").exists():
        import subprocess
        subprocess.run([sys.executable, str(ROOT / "scripts" / "generate_sample_data.py")], check=True)
    return docs
