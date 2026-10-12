"""
aml_sanctions_checker.py — Stage 2: screen a customer against sanctions lists.

Input : customer name (+ optional nationality, date of birth, aliases)
Output: JSON dict
        {
          "status": "MATCH" | "POTENTIAL_MATCH" | "NO_MATCH",
          "top_score": 0.0-1.0,
          "matches": [ {uid, list, matched_name, name_score, final_score,
                        adjustments, ...} ],
          "requires_review": bool, "explanation": str, ...
        }

Why not exact matching?
-----------------------
Arabic names are transliterated many ways ("Mohammed / Muhammad / Mohamed",
"Al-Rashidi / Alrashidi / El Rashidi", "bin / ibn"). Exact matching misses
true hits; naive fuzzy matching drowns analysts in false positives.

This module uses a 3-step approach that mirrors commercial screening engines:

1. NORMALISE  – lower-case, strip diacritics/punctuation, drop particles
                (al-, el-, bin, ibn, bint), map transliteration variants to a
                canonical form (muhammad, abdullah, yusuf, husayn, ...).
2. FUZZY NAME – token-sort and token-set similarity (order-independent),
                take the best of primary name and all AKAs.
3. SECONDARY  – adjust the score with secondary identifiers to cut false
   IDENTIFIERS  positives: DOB and nationality agreement raise it, clear
                disagreement lowers it. Every adjustment is recorded so the
                decision is explainable to an auditor.

Thresholds live in config.py (MATCH >= 0.90, POTENTIAL_MATCH >= 0.80).
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime, timezone
from difflib import SequenceMatcher
from functools import lru_cache
from pathlib import Path
from typing import Any

import config

logger = config.get_logger("sanctions")

PARTICLES = {"al", "el", "bin", "ibn", "bint", "ben", "binti", "mr", "mrs", "dr", "sheikh", "shaikh"}

# Western names that genuinely start with "al" — never strip the prefix
NON_ARABIC_AL = {"alexander", "alexandra", "alexandre", "albert", "alberto", "alfred", "alfredo",
                 "alison", "allison", "alvaro", "alessandro", "alejandro", "alistair", "alberta"}

# Transliteration variants -> canonical token
VARIANTS = {
    "muhammad": ["mohammed", "mohammad", "mohamed", "mohamad", "muhammed", "muhamad", "mohd", "mhd", "mohammod"],
    "ahmad": ["ahmed", "ahmet"],
    "abdullah": ["abdallah", "abdulla", "abdalla", "abdella"],
    "abdulrahman": ["abdurrahman", "abdelrahman", "abdalrahman"],
    "abdulaziz": ["abdelaziz", "abdalaziz"],
    "yusuf": ["yousef", "youssef", "yousif", "yusef", "yosef", "joseph"],
    "husayn": ["hussein", "husain", "hussain", "husein", "hossein"],
    "hasan": ["hassan"],
    "khalid": ["khaled", "khalied"],
    "umar": ["omar", "omer"],
    "usama": ["osama", "ousama"],
    "faisal": ["faysal", "feisal"],
    "ibrahim": ["ebrahim", "ibraheem"],
    "mustafa": ["mostafa", "moustafa"],
    "sulayman": ["suleiman", "sulaiman", "suleyman", "sleiman"],
    "tariq": ["tarek", "tareq", "tarik"],
    "nasir": ["nasser", "naser", "nassir"],
    "jamal": ["gamal"],
    "said": ["saeed", "sayed", "saied", "sayeed"],
    "salih": ["saleh"],
    "abbas": ["abass"],
    "ali": ["aly"],
    "rashid": ["rasheed", "rached"],
    "rashidi": ["rasheedi"],
    "zubayr": ["zubair", "zubeir"],
    "qasim": ["kassem", "qassem", "qassim", "kasim"],
}
CANONICAL = {v: k for k, vs in VARIANTS.items() for v in vs}


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #
def normalise_name(name: str) -> list[str]:
    """Return canonical tokens for a name."""
    if not name:
        return []
    text = unicodedata.normalize("NFKD", name)
    text = "".join(ch for ch in text if not unicodedata.combining(ch)).lower()
    # "abd al rahman" / "abdel rahman" / "abdul rahman" -> "abdulrahman"
    text = re.sub(r"\babd(?:ul|el|al)?[\s\-]+(?:al[\s\-]+)?(\w+)", r"abdul\1", text)
    text = re.sub(r"\b(al|el)-", " ", text)         # al-rashidi -> rashidi
    text = re.sub(r"[^a-z\s]", " ", text)
    tokens = []
    for tok in text.split():
        if tok in PARTICLES:
            continue
        if tok.startswith("al") and len(tok) >= 6 and tok not in NON_ARABIC_AL:
            tok = tok[2:]  # alrashidi -> rashidi (attached Arabic article)
        tok = CANONICAL.get(tok, tok)
        tok = re.sub(r"(.)\1+", r"\1", tok)              # collapse doubled letters
        tokens.append(tok)
    # Normalise "abdul..." forms after collapse
    return [CANONICAL.get(t, t) for t in tokens]


TOKEN_MATCH_FLOOR = 0.80


def _ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def name_similarity(query: str, candidate: str) -> float:
    """Order-independent similarity in [0,1]."""
    q, c = normalise_name(query), normalise_name(candidate)
    if not q or not c:
        return 0.0
    token_sort = _ratio(" ".join(sorted(q)), " ".join(sorted(c)))

    def directional(a: list[str], b: list[str]) -> float:
        # Each name part counts equally; a part with no close counterpart
        # (best ratio < TOKEN_MATCH_FLOOR) contributes 0 instead of partial credit.
        scores = [max(_ratio(t, u) for u in b) for t in a]
        return sum(s if s >= TOKEN_MATCH_FLOOR else 0.0 for s in scores) / len(scores)

    # Symmetric token-set: penalises extra/missing name parts on either side
    token_set = (directional(q, c) + directional(c, q)) / 2
    return round(max(token_sort, token_set), 4)


# --------------------------------------------------------------------------- #
# List loading
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=4)
def load_sanctions_list(path: str | None = None) -> dict:
    p = Path(path or config.SANCTIONS_LIST_PATH)
    with open(p, encoding="utf-8") as fh:
        data = json.load(fh)
    if "entries" not in data:
        raise ValueError(f"Sanctions file {p} has no 'entries' array")
    logger.info("Loaded %d sanctions entries (version %s)", len(data["entries"]),
                data.get("metadata", {}).get("version"))
    return data


# --------------------------------------------------------------------------- #
# Screening
# --------------------------------------------------------------------------- #
def screen_customer(name: str, nationality: str | None = None, date_of_birth: str | None = None,
                    aliases: list[str] | None = None, entity_type: str = "individual",
                    sanctions_path: str | None = None) -> dict:
    """Screen a customer. Main entry point."""
    if not name or not name.strip():
        raise ValueError("Customer name is required for screening")

    data = load_sanctions_list(str(sanctions_path) if sanctions_path else None)
    names_to_check = [name] + list(aliases or [])
    review_floor = 0.75  # candidates kept for the analyst view
    matches: list[dict[str, Any]] = []

    for entry in data["entries"]:
        if entry.get("type", "individual") != entity_type:
            continue
        candidates = [(entry["name"], "primary")] + [(a, "aka") for a in entry.get("aka", [])]
        best_score, best_name, best_on = 0.0, None, None
        for q in names_to_check:
            for cand, kind in candidates:
                s = name_similarity(q, cand)
                if s > best_score:
                    best_score, best_name, best_on = s, cand, kind
        if best_score < review_floor:
            continue

        final, adjustments = _apply_secondary_identifiers(best_score, entry, nationality, date_of_birth)
        matches.append({
            "uid": entry["uid"],
            "list": entry["list"],
            "listed_name": entry["name"],
            "matched_name": best_name,
            "matched_on": best_on,
            "programs": entry.get("programs", []),
            "listed_nationality": entry.get("nationality"),
            "listed_dob": entry.get("dob"),
            "name_score": round(best_score, 4),
            "final_score": round(final, 4),
            "adjustments": adjustments,
            "decision": _classify(final),
        })

    matches.sort(key=lambda m: m["final_score"], reverse=True)
    matches = matches[:5]
    top = matches[0]["final_score"] if matches else 0.0
    status = _classify(top)

    result = {
        "status": status,
        "top_score": round(top, 4),
        "screened_name": name,
        "screened_nationality": nationality,
        "screened_dob": date_of_birth,
        "normalised_tokens": normalise_name(name),
        "lists_checked": sorted({e["list"] for e in data["entries"]}),
        "list_version": data.get("metadata", {}).get("version"),
        "entries_screened": len(data["entries"]),
        "thresholds": {"match": config.SANCTIONS_MATCH_THRESHOLD,
                       "potential_match": config.SANCTIONS_POTENTIAL_MATCH_THRESHOLD},
        "matches": matches,
        "requires_review": status != "NO_MATCH",
        "explanation": _explain(status, matches),
        "screened_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    logger.info("Screened '%s' -> %s (top %.2f)", name, status, top)
    return result


def _apply_secondary_identifiers(score: float, entry: dict, nationality: str | None,
                                 dob: str | None) -> tuple[float, list[str]]:
    adj: list[str] = []
    listed_dob = entry.get("dob")
    if dob and listed_dob:
        if dob == listed_dob:
            score += 0.05
            adj.append("+0.05 date of birth exact match")
        elif dob[:4] == listed_dob[:4]:
            score += 0.02
            adj.append("+0.02 birth year match")
        elif abs(int(dob[:4]) - int(listed_dob[:4])) > 2:
            score -= 0.15
            adj.append(f"-0.15 birth year differs ({dob[:4]} vs {listed_dob[:4]})")
    listed_nat = entry.get("nationality")
    if nationality and listed_nat:
        if nationality.upper() == listed_nat.upper():
            score += 0.03
            adj.append("+0.03 nationality match")
        else:
            score -= 0.10
            adj.append(f"-0.10 nationality differs ({nationality} vs {listed_nat})")
    return max(0.0, min(1.0, score)), adj


def _classify(score: float) -> str:
    if score >= config.SANCTIONS_MATCH_THRESHOLD:
        return "MATCH"
    if score >= config.SANCTIONS_POTENTIAL_MATCH_THRESHOLD:
        return "POTENTIAL_MATCH"
    return "NO_MATCH"


def _explain(status: str, matches: list[dict]) -> str:
    if status == "NO_MATCH" and not matches:
        return "No list entry scored above the review floor. Customer cleared for sanctions."
    if status == "NO_MATCH":
        m = matches[0]
        return (f"Closest candidate '{m['listed_name']}' ({m['uid']}) scored {m['final_score']:.2f} after "
                f"secondary-identifier checks ({'; '.join(m['adjustments']) or 'none'}) — below threshold; "
                f"treated as a false positive and auto-cleared.")
    m = matches[0]
    action = ("Onboarding must be BLOCKED and the case escalated to the MLRO; "
              "a confirmed hit requires asset freeze and reporting per SAMA/UN obligations."
              if status == "MATCH" else
              "Requires analyst review to confirm or discount before onboarding proceeds.")
    return (f"{status}: '{m['matched_name']}' on {m['list']} ({m['uid']}, programs: "
            f"{', '.join(m['programs']) or 'n/a'}) — name score {m['name_score']:.2f}, "
            f"final {m['final_score']:.2f}. {action}")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Screen a name against the sanctions list")
    p.add_argument("name")
    p.add_argument("--nationality")
    p.add_argument("--dob", help="YYYY-MM-DD")
    a = p.parse_args()
    print(json.dumps(screen_customer(a.name, a.nationality, a.dob), indent=2, ensure_ascii=False))
