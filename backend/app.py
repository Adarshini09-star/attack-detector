"""
backend/app.py  — PhishNet FastAPI Backend
==========================================
Run:   uvicorn backend.app:app --reload
Or:    cd project && uvicorn backend.app:app --reload --port 8000

Requirements:  pip install fastapi uvicorn scikit-learn numpy anthropic python-multipart
Set env var:   export ANTHROPIC_API_KEY=sk-ant-...
"""

import os
import re
import pickle
import pathlib
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── optional AI enrichment ────────────────────────────────
try:
    import anthropic
    _ai_client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
    _AI_AVAILABLE = bool(os.environ.get("ANTHROPIC_API_KEY"))
except ImportError:
    _ai_client = None
    _AI_AVAILABLE = False

# ── ML models ─────────────────────────────────────────────
ROOT = pathlib.Path(__file__).parent.parent   # project root

def _load_pickle(path: pathlib.Path):
    with open(path, "rb") as f:
        return pickle.load(f)

try:
    TEXT_MODEL  = _load_pickle(ROOT / "ml" / "text_model.pkl")
    VECTORIZER  = _load_pickle(ROOT / "ml" / "vectorizer.pkl")
    _ML_READY   = True
    print("✅ ML models loaded")
except Exception as e:
    TEXT_MODEL = VECTORIZER = None
    _ML_READY  = False
    print(f"⚠️  ML models not found ({e}). Run ml/train_text_model.py first.")

# ── URL scorer ────────────────────────────────────────────
import sys
sys.path.insert(0, str(ROOT))
from url_detection.url_features import score_url

# ── APP ───────────────────────────────────────────────────
app = FastAPI(
    title="PhishNet API",
    description="AI-powered phishing & social engineering detector",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── SCHEMAS ───────────────────────────────────────────────
class TextRequest(BaseModel):
    message: str
    lang: str = "en"          # en | hi | kn
    use_ai: bool = True       # enrich with Claude if key available

class URLRequest(BaseModel):
    url: str
    lang: str = "en"
    use_ai: bool = True

# ── CONSTANTS ─────────────────────────────────────────────
LANG_MAP  = {"en": "English", "hi": "Hindi", "kn": "Kannada"}

SAFETY_TIPS = [
    "Do not click links from unknown or suspicious messages.",
    "Verify the sender's identity before responding.",
    "Never share passwords, OTPs, or banking details.",
    "Always access services through official websites.",
    "Report suspicious messages to your IT team or service provider.",
]

TACTIC_MAP = {
    r"urgent|immediately|now|asap|act fast|deadline|expire|24 hour|limited time": "Urgency",
    r"bank|account|paypal|netflix|amazon|microsoft|apple|google|irs|social security": "Authority Impersonation",
    r"suspend|block|arrest|penalty|fine|lose access|terminated|legal action": "Fear / Threat",
    r"free|won|winner|prize|gift|reward|claim|congratulation|selected": "Reward Bait",
    r"verify|confirm|validate|update.*info|click here|login|credential": "Credential Harvesting",
    r"password|otp|pin|security code|card number|cvv|ssn": "Sensitive Data Request",
}

def detect_tactics(text: str) -> list[str]:
    found = []
    tl = text.lower()
    for pattern, label in TACTIC_MAP.items():
        if re.search(pattern, tl) and label not in found:
            found.append(label)
    return found if found else ["No clear tactics detected"]

SCORE_TO_RISK = [(60, "High"), (30, "Medium"), (0, "Low")]

def bucket(score: float) -> str:
    for threshold, label in SCORE_TO_RISK:
        if score >= threshold:
            return label
    return "Low"

# ── AI ENRICHMENT ─────────────────────────────────────────
def _ai_explain(prompt: str) -> Optional[str]:
    if not _AI_AVAILABLE or _ai_client is None:
        return None
    try:
        resp = _ai_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}]
        )
        return resp.content[0].text.strip()
    except Exception:
        return None


# ══════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════

@app.get("/")
def root():
    return {
        "status":    "PhishNet API running",
        "ml_ready":  _ML_READY,
        "ai_ready":  _AI_AVAILABLE,
        "version":   "1.0.0"
    }

@app.get("/health")
def health():
    return {"status": "ok", "ml": _ML_READY, "ai": _AI_AVAILABLE}


# ── TEXT ANALYSIS ─────────────────────────────────────────
@app.post("/analyze-text")
def analyze_text(req: TextRequest):
    msg = req.message.strip()
    if not msg:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    # 1. ML prediction
    ml_score   = 50          # fallback if models not loaded
    ml_label   = "Social Engineering"

    if _ML_READY:
        vec      = VECTORIZER.transform([msg])
        prob     = TEXT_MODEL.predict_proba(vec)[0]   # [P(legit), P(phishing)]
        phish_p  = float(prob[1])
        ml_score = round(phish_p * 100, 1)
        ml_label = "Social Engineering" if phish_p >= 0.5 else "Legitimate Message"

    # 2. Rule-based tactic detection
    tactics  = detect_tactics(msg)
    tactic_bonus = min(len([t for t in tactics if t != "No clear tactics detected"]) * 8, 25)

    final_score = min(round(ml_score + tactic_bonus), 100)
    risk_level  = bucket(final_score)

    # 3. AI explanation (optional)
    explanation = (
        "This message contains patterns commonly associated with social engineering attacks. "
        "Attackers use psychological manipulation to pressure victims into taking immediate action."
    )

    if req.use_ai and _AI_AVAILABLE:
        lang    = LANG_MAP.get(req.lang, "English")
        ai_resp = _ai_explain(
            f"You are a cybersecurity expert. In 2 sentences, explain why this message "
            f"is {risk_level.lower()} risk for phishing or social engineering. "
            f"Respond in {lang}. Message: \"{msg}\""
        )
        if ai_resp:
            explanation = ai_resp

    return {
        "risk_level":  risk_level,
        "score":       final_score,
        "prediction":  ml_label,
        "tactics":     tactics,
        "explanation": explanation,
        "safety_tips": SAFETY_TIPS,
    }


# ── URL ANALYSIS ──────────────────────────────────────────
@app.post("/analyze-url")
def analyze_url(req: URLRequest):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # 1. Rule-based URL scoring
    result     = score_url(url)
    risk_level = result["risk_level"]
    score      = result["score"]
    issues     = result["issues"]

    # 2. Prediction label
    prediction = (
        "Phishing URL"      if risk_level == "High"
        else "Suspicious URL" if risk_level == "Medium"
        else "Likely Safe URL"
    )

    # 3. AI explanation (optional)
    explanation = (
        "This URL contains structural patterns commonly found in phishing attacks, "
        "such as suspicious domains, keywords, or encoding techniques."
    )

    if req.use_ai and _AI_AVAILABLE:
        lang    = LANG_MAP.get(req.lang, "English")
        issues_str = ", ".join(issues[:4])
        ai_resp = _ai_explain(
            f"You are a cybersecurity expert. In 2 sentences, explain why this URL is "
            f"{risk_level.lower()} risk. Issues found: {issues_str}. "
            f"URL: {url}. Respond in {lang}."
        )
        if ai_resp:
            explanation = ai_resp

    return {
        "risk_level":  risk_level,
        "score":       score,
        "prediction":  prediction,
        "issues":      issues,
        "explanation": explanation,
        "safety_tips": SAFETY_TIPS,
    }
