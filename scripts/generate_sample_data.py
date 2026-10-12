"""
generate_sample_data.py — Render the sample KYC documents from test_cases.json.

    python scripts/generate_sample_data.py

* PDF cases -> a text-based "Customer Onboarding (KYC) Form" (works in offline
  mode AND with Claude).
* PNG cases -> a 'scanned' ID card image with no text layer (Claude vision only).

Every document is stamped as FICTITIOUS SAMPLE DATA and uses a fictitious bank.
"""

from __future__ import annotations

import json
import random
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "sample_kyc_documents"
BANK = "Najd Digital Bank (fictitious)"

SECTIONS = [
    ("A. Identity", [("full_name", "Full Name"), ("id_type", "ID Type"), ("id_number", "ID Number"),
                     ("nationality", "Nationality"), ("date_of_birth", "Date of Birth"), ("gender", "Gender"),
                     ("id_issue_date", "ID Issue Date"), ("id_expiry_date", "ID Expiry Date")]),
    ("B. Contact & Residence", [("address", "Address"), ("city", "City"),
                                ("country_of_residence", "Country of Residence"), ("phone", "Phone"),
                                ("email", "Email")]),
    ("C. Employment & Financial Profile", [("occupation", "Occupation"), ("employer", "Employer"),
                                           ("business_type", "Business Type"),
                                           ("monthly_income_sar", "Monthly Income (SAR)"),
                                           ("expected_monthly_volume_sar", "Expected Monthly Transactions (SAR)"),
                                           ("source_of_funds", "Source of Funds"),
                                           ("purpose_of_account", "Purpose of Account")]),
    ("D. Declarations", [("pep_status", "Politically Exposed Person"), ("pep_details", "PEP Details")]),
]
DATE_FIELDS = {"date_of_birth", "id_issue_date", "id_expiry_date"}


def fmt(key: str, value: str | None) -> str:
    if not value:
        return ""
    if key in DATE_FIELDS:  # print as DD/MM/YYYY to exercise date normalisation
        return datetime.strptime(value, "%Y-%m-%d").strftime("%d/%m/%Y")
    return str(value)


def render_pdf(case: dict, path: Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas

    c = case["customer"]
    w, h = A4
    pdf = canvas.Canvas(str(path), pagesize=A4)
    pdf.setTitle(f"KYC Form - {c['full_name']} (sample)")

    pdf.setFillColor(colors.HexColor("#0B4F6C"))
    pdf.rect(0, h - 32 * mm, w, 32 * mm, fill=1, stroke=0)
    pdf.setFillColor(colors.white)
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(20 * mm, h - 15 * mm, BANK)
    pdf.setFont("Helvetica", 11)
    pdf.drawString(20 * mm, h - 23 * mm, "Customer Onboarding - Know Your Customer (KYC) Form")

    pdf.setFillColor(colors.HexColor("#B42318"))
    pdf.setFont("Helvetica-Bold", 8)
    pdf.drawString(20 * mm, h - 39 * mm, "SAMPLE DOCUMENT - FICTITIOUS DATA - NOT AN OFFICIAL FORM - FOR SOFTWARE TESTING ONLY")
    pdf.setFillColor(colors.black)
    pdf.setFont("Helvetica", 8)
    pdf.drawString(20 * mm, h - 44 * mm, f"Application ref: APP-{case['id']}-2026    Branch: Digital onboarding")

    y = h - 56 * mm
    for title, fields in SECTIONS:
        pdf.setFont("Helvetica-Bold", 11)
        pdf.setFillColor(colors.HexColor("#0B4F6C"))
        pdf.drawString(20 * mm, y, title)
        pdf.setStrokeColor(colors.HexColor("#D0D5DD"))
        pdf.line(20 * mm, y - 2 * mm, w - 20 * mm, y - 2 * mm)
        pdf.setFillColor(colors.black)
        y -= 8 * mm
        for key, label in fields:
            if key not in c and key not in ("occupation", "employer"):
                continue
            pdf.setFont("Helvetica", 10)
            # Single text run per line so text extraction yields "Label: value"
            pdf.drawString(24 * mm, y, f"{label}: {fmt(key, c.get(key))}")
            y -= 6.5 * mm
        y -= 4 * mm

    pdf.setFont("Helvetica-Oblique", 8)
    pdf.drawString(20 * mm, y - 2 * mm, "I confirm the information above is true and complete.")
    pdf.drawString(20 * mm, y - 8 * mm, "Customer signature: ______________________    Date: ____________")
    pdf.setFont("Helvetica", 7)
    pdf.setFillColor(colors.HexColor("#667085"))
    pdf.drawString(20 * mm, 12 * mm, "All names, ID numbers and companies in this document are invented for testing a KYC/AML automation proof-of-concept.")
    pdf.save()


def render_png(case: dict, path: Path) -> None:
    from PIL import Image, ImageDraw, ImageFilter, ImageFont

    c = case["customer"]
    W, H = 1100, 690
    img = Image.new("RGB", (W, H), "#EEF4F1")
    d = ImageDraw.Draw(img)

    def font(size: int, bold: bool = False):
        for name in (["DejaVuSans-Bold.ttf"] if bold else ["DejaVuSans.ttf"]):
            try:
                return ImageFont.truetype(name, size)
            except OSError:
                pass
        return ImageFont.load_default(size=size)

    d.rounded_rectangle([20, 20, W - 20, H - 20], radius=28, outline="#2E6B57", width=4, fill="#F7FBF9")
    d.rectangle([20, 20, W - 20, 110], fill="#2E6B57")
    d.text((50, 38), "RESIDENT IDENTITY CARD", font=font(34, True), fill="white")
    d.text((50, 80), "SAMPLE / FICTITIOUS - NOT A REAL DOCUMENT", font=font(16), fill="#FDE68A")
    d.rectangle([50, 150, 290, 450], outline="#94A3B8", width=3, fill="#E2E8F0")
    d.text((110, 290), "PHOTO", font=font(30, True), fill="#94A3B8")

    rows = [("Name", c["full_name"]), ("ID No.", c["id_number"]), ("Nationality", c["nationality"]),
            ("Date of Birth", fmt("date_of_birth", c["date_of_birth"])), ("Gender", c["gender"]),
            ("Occupation", c["occupation"]), ("Employer", c.get("employer", "")),
            ("Issue Date", fmt("id_issue_date", c["id_issue_date"])),
            ("Expiry Date", fmt("id_expiry_date", c["id_expiry_date"])), ("City", c.get("city", ""))]
    y = 140
    for label, value in rows:
        d.text((330, y), label, font=font(17), fill="#475569")
        d.text((520, y), str(value), font=font(22, True), fill="#0F172A")
        y += 46
    d.text((50, H - 70), f"<<{c['id_number']}<<{c['full_name'].upper().replace(' ', '<')}<<<<<<<<",
           font=font(20), fill="#334155")

    # Make it look like a phone scan: slight rotation, blur, noise
    random.seed(7)
    img = img.rotate(1.6, expand=True, fillcolor="#C9CCCF").filter(ImageFilter.GaussianBlur(0.6))
    px = img.load()
    for _ in range(9000):
        x, yy = random.randrange(img.width), random.randrange(img.height)
        v = random.randint(-30, 30)
        r, g, b = px[x, yy]
        px[x, yy] = (max(0, min(255, r + v)), max(0, min(255, g + v)), max(0, min(255, b + v)))
    img.save(path, "PNG", optimize=True)


def main() -> int:
    cases = json.loads((ROOT / "test_cases.json").read_text(encoding="utf-8"))["document_cases"]
    OUT.mkdir(exist_ok=True)
    for case in cases:
        path = OUT / case["document"]
        (render_png if path.suffix == ".png" else render_pdf)(case, path)
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
