"""
backend/app.py — PhishNet v3.1
Smart detection: avoids false positives on real bank alerts, OTPs, UPI transactions
"""

import os, re, pickle, pathlib
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── Claude AI ─────────────────────────────────
try:
    import anthropic
    _ai_client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
    _AI_AVAILABLE = bool(os.environ.get("ANTHROPIC_API_KEY"))
except ImportError:
    _ai_client = None
    _AI_AVAILABLE = False

# ── ML Models ─────────────────────────────────
ROOT = pathlib.Path(__file__).parent.parent

def _load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)

try:
    TEXT_MODEL = _load_pickle(ROOT / "ml" / "text_model.pkl")
    VECTORIZER = _load_pickle(ROOT / "ml" / "vectorizer.pkl")
    _ML_READY  = True
    print("✅ ML models loaded")
except Exception as e:
    TEXT_MODEL = VECTORIZER = None
    _ML_READY  = False
    print(f"⚠️  ML models not found: {e}")

import sys
sys.path.insert(0, str(ROOT))
from url_detection.url_features import score_url

app = FastAPI(title="PhishNet API", version="3.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

try:
    app.mount("/app", StaticFiles(directory=str(ROOT / "frontend"), html=True), name="frontend")
except:
    pass

# ── Schemas ───────────────────────────────────
class TextRequest(BaseModel):
    message: str
    lang: str = "en"
    use_ai: bool = True

class URLRequest(BaseModel):
    url: str
    lang: str = "en"
    use_ai: bool = True

# ── Constants ─────────────────────────────────
LANG_MAP = {"en": "English", "hi": "Hindi", "kn": "Kannada"}

SAFETY_TIPS = [
    "Do not click links from unknown or suspicious messages.",
    "Verify the sender's identity before responding.",
    "Never share passwords, OTPs, or banking details with anyone who asks.",
    "Always access services through official apps or websites.",
    "Report suspicious messages to your bank or service provider.",
]

# ── Trusted sender patterns ───────────────────
TRUSTED_DOMAINS = [
    r'alerts?\.(hdfc|icici|sbi|axis|kotak|yes|pnb|canara|indusind)bank',
    r'(hdfc|icici|sbi|axis|kotak)bank\.com',
    r'noreply@paytm\.com', r'alerts@phonepe',
    r'@(visa|mastercard|rupay)\.com',
]
TRUSTED_RE = re.compile('|'.join(TRUSTED_DOMAINS), re.I)

# ── Legitimate transaction patterns ──────────
LEGIT_PATTERNS = [
    re.compile(r'Rs\.?\s*\d+.*(?:debited|credited|transferred)', re.I),
    re.compile(r'UPI\s*(?:transaction|txn|ref)\s*(?:no|number|id)?\.?\s*[:#]?\s*\d{6,}', re.I),
    re.compile(r'(?:debited|credited)\s*from\s*(?:account|a\/c|VPA)', re.I),
    re.compile(r'OTP\s*(?:for|is|:)\s*\d{4,8}', re.I),
    re.compile(r'\d{4,8}\s*is\s*(?:your|the)\s*(?:otp|one.time)', re.I),
    re.compile(r'available\s*balance\s*(?:is|:)\s*Rs', re.I),
    re.compile(r'a\/c\s*(?:no\.?)?\s*[xX*]+\d{4}', re.I),
    re.compile(r'NEFT|RTGS|IMPS|NACH', re.I),
]

# ── Strong phishing signals ───────────────────
STRONG_PHISHING = [
    re.compile(r'click\s*(?:here|this\s*link|now)\s*(?:to\s*)?(?:verify|confirm|update|login|reset|claim)', re.I),
    re.compile(r'your\s*account\s*(?:will\s*be|has\s*been)\s*(?:suspended|blocked|terminated|closed|deleted)', re.I),
    re.compile(r'(?:avoid|prevent)\s*(?:arrest|penalty|legal\s*action)\s*(?:by\s*)?(?:clicking|paying|calling)', re.I),
    re.compile(r'you\s*(?:have\s*)?(?:won|been\s*selected)\s*(?:a\s*)?\$[\d,]+', re.I),
    re.compile(r'claim\s*your\s*(?:prize|reward|gift|winnings)\s*(?:now|immediately)', re.I),
    re.compile(r'your\s*(?:password|credentials)\s*(?:has\s*been\s*compromised|were\s*exposed)', re.I),
    re.compile(r'transfer\s*funds?\s*of\s*\$[\d,]+\s*(?:million|thousand)', re.I),
    re.compile(r'your\s*(?:computer|device)\s*has\s*a?\s*virus', re.I),
    re.compile(r'call\s*(?:microsoft|apple|google)\s*support\s*(?:immediately|now)', re.I),
]

# ── Tactic detection (context-aware) ─────────
TACTICS = {
    r"urgent|act fast|deadline|expires? (?:today|tonight|now)|24.hour": "Urgency",
    r"suspend|block|arrest|penalty|fine|lose access|terminated|legal action": "Fear / Threat",
    r"won|winner|prize|gift|reward|claim|congratulation|lucky": "Reward Bait",
    r"click here.*(?:verify|login|reset)|credential": "Credential Harvesting",
    r"password|otp|pin|cvv|ssn": "Sensitive Data Request",
}
# Whitelist: don't count tactic if these are present
TACTIC_WHITELIST = re.compile(
    r'Rs\.?\s*\d+|debited|credited|UPI|transaction|VPA|balance|otp is|otp for|\d{4,8}\s*is your', re.I
)

def detect_tactics(text: str) -> list:
    tl = text.lower()
    found = []
    is_legit_context = TACTIC_WHITELIST.search(text)
    for pattern, label in TACTICS.items():
        if re.search(pattern, tl, re.I):
            if is_legit_context and label in ('Urgency', 'Sensitive Data Request'):
                continue  # skip in legit context
            found.append(label)
    return found if found else ["No clear tactics detected"]

def is_legitimate_message(text: str) -> bool:
    return any(p.search(text) for p in LEGIT_PATTERNS)

def has_strong_phishing(text: str) -> bool:
    return any(p.search(text) for p in STRONG_PHISHING)

def bucket(score: float) -> str:
    if score >= 60: return "High"
    if score >= 35: return "Medium"
    return "Low"

# ── Claude AI with smart prompt ───────────────
def _ai_explain(prompt: str) -> Optional[str]:
    if not _AI_AVAILABLE or not _ai_client:
        return None
    try:
        resp = _ai_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}]
        )
        return resp.content[0].text.strip()
    except Exception as e:
        print(f"AI error: {e}")
        return None

# ── Routes ────────────────────────────────────
@app.get("/")
def root():
    return {"status": "PhishNet API v3.1", "ml_ready": _ML_READY, "ai_ready": _AI_AVAILABLE}

@app.get("/health")
def health():
    return {"status": "ok", "ml": _ML_READY, "ai": _AI_AVAILABLE}

@app.post("/analyze-text")
def analyze_text(req: TextRequest):
    msg = req.message.strip()
    if not msg:
        raise HTTPException(400, "Message cannot be empty.")

    # ── Smart pre-checks ──────────────────────
    legit    = is_legitimate_message(msg)
    strong_p = has_strong_phishing(msg)

    # ── ML Model prediction ───────────────────
    ml_score = 50
    ml_label = "Unknown"
    ml_confidence = None

    if _ML_READY:
        vec   = VECTORIZER.transform([msg])
        prob  = TEXT_MODEL.predict_proba(vec)[0]
        phish = float(prob[1])

        # Correct for ML bias on legitimate bank messages:
        # The training data (SMS spam) flags "bank", "account", "verify" as spam
        # but real bank alerts use these words legitimately
        if legit and not strong_p:
            phish = min(phish, 0.25)  # cap at 25% for confirmed legitimate messages

        ml_score      = round(phish * 100, 1)
        ml_label      = "Social Engineering" if phish >= 0.5 else "Legitimate Message"
        ml_confidence = round(max(prob) * 100, 1)

    # ── Tactic detection ──────────────────────
    tactics      = detect_tactics(msg)
    clean_tactics = [t for t in tactics if t != "No clear tactics detected"]

    # Tactic bonus — only apply for non-legitimate messages
    tactic_bonus = 0 if (legit and not strong_p) else min(len(clean_tactics) * 7, 20)

    # ── Final score ───────────────────────────
    if strong_p:
        final_score = max(ml_score + tactic_bonus, 65)   # always High if strong signal
    elif legit:
        final_score = min(ml_score + tactic_bonus, 28)   # always Low if legit
    else:
        final_score = ml_score + tactic_bonus

    final_score = min(round(final_score), 100)
    risk_level  = bucket(final_score)

    # ── Explanation ───────────────────────────
    if legit and not strong_p:
        explanation = "This appears to be a legitimate transactional notification from a financial institution. No deceptive intent detected."
    else:
        explanation = "This message contains patterns associated with social engineering attacks."

    if req.use_ai and _AI_AVAILABLE:
        lang = LANG_MAP.get(req.lang, "English")
        context_note = ""
        if legit:
            context_note = "NOTE: This message matches a legitimate bank transaction format. Only flag if it additionally tries to trick the user into clicking a link or sharing credentials. "
        ai_resp = _ai_explain(
            f"You are a cybersecurity expert. {context_note}"
            f"In 2 sentences, explain why this message is {risk_level.lower()} risk "
            f"for phishing or social engineering. Respond in {lang}. "
            f"Message: \"{msg[:400]}\""
        )
        if ai_resp:
            explanation = ai_resp

    return {
        "risk_level":    risk_level,
        "score":         final_score,
        "prediction":    ml_label,
        "ml_score":      ml_score,
        "ml_confidence": ml_confidence,
        "tactics":       tactics,
        "explanation":   explanation,
        "safety_tips":   SAFETY_TIPS,
        "ml_used":       _ML_READY,
        "ai_used":       _AI_AVAILABLE and req.use_ai,
        "is_legitimate": legit and not strong_p,
    }

@app.post("/analyze-url")
def analyze_url(req: URLRequest):
    url = req.url.strip()
    if not url:
        raise HTTPException(400, "URL cannot be empty.")

    result     = score_url(url)
    risk_level = result["risk_level"]
    score      = result["score"]
    issues     = result["issues"]
    prediction = "Phishing URL" if risk_level=="High" else "Suspicious URL" if risk_level=="Medium" else "Likely Safe URL"

    explanation = "This URL contains structural patterns commonly found in phishing attacks."
    if req.use_ai and _AI_AVAILABLE:
        lang       = LANG_MAP.get(req.lang, "English")
        issues_str = ", ".join(issues[:4])
        ai_resp    = _ai_explain(
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
        "ai_used":     _AI_AVAILABLE and req.use_ai,
    }
