import os
import re
import base64
import pickle
import pathlib
import io
from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import google.generativeai as genai

# ── Config ────────────────────────────────────────────────────────────────────
GEMINI_API_KEY = "AIzaSyDrooFZywYTU_dXqOhjDka3HTJfx1pdcJM"   # ← replace with your key
GEMINI_MODEL   = "gemini-1.5-flash-latest"           # generous free-tier model

genai.configure(api_key=GEMINI_API_KEY)

ROOT = pathlib.Path(__file__).parent.parent           # project root
ML_DIR = ROOT / "ml"

# ── Load ML model ─────────────────────────────────────────────────────────────
try:
    with open(ML_DIR / "text_model.pkl", "rb") as f:
        text_model = pickle.load(f)
    with open(ML_DIR / "vectorizer.pkl", "rb") as f:
        vectorizer = pickle.load(f)
    ML_LOADED = True
    print("✅ ML model loaded")
except Exception as e:
    ML_LOADED = False
    print(f"⚠️  ML model not found: {e}")

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(title="PhishNet API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

try:
    app.mount("/app", StaticFiles(directory=str(ROOT / "frontend"), html=True), name="frontend")
except Exception:
    pass

# ── Schemas ───────────────────────────────────────────────────────────────────
class TextRequest(BaseModel):
    message: str

class URLRequest(BaseModel):
    url: str

# ── Phishing keywords ─────────────────────────────────────────────────────────
PHISHING_KEYWORDS = [
    "verify", "account", "suspended", "urgent", "click here", "login",
    "password", "otp", "bank", "credit card", "prize", "winner", "free",
    "confirm", "update", "limited time", "act now", "congratulations",
    "security alert", "unusual activity", "locked", "expire", "claim",
    "kyc", "refund", "tax", "irs", "customs", "parcel"
]

# ── Gemini helpers ────────────────────────────────────────────────────────────
def gemini_explain(content: str, content_type: str, risk_level: str, score: int, keywords: list) -> dict:
    """Generate AI explanation + safety tips using Gemini."""
    keywords_str = ", ".join(keywords) if keywords else "none detected"
    prompt = f"""You are a cybersecurity expert analyzing a potentially suspicious {content_type}.

Content: {content[:500]}
Risk Level: {risk_level} ({score}/100)
Flagged indicators: {keywords_str}

Respond in this EXACT JSON format (no markdown, no backticks):
{{
  "explanation": "2-3 sentence expert analysis of WHY this is {risk_level} risk. Be specific about the exact tactics used or why it appears legitimate.",
  "safety_tips": [
    "Specific tip 1 relevant to this exact message",
    "Specific tip 2 relevant to this content",
    "General best practice tip",
    "What to do if you already interacted",
    "How to verify if this is legitimate"
  ]
}}"""

    try:
        model = genai.GenerativeModel(GEMINI_MODEL)
        response = model.generate_content(prompt)
        text = response.text.strip()
        # strip markdown fences if present
        text = re.sub(r"```json|```", "", text).strip()
        import json
        parsed = json.loads(text)
        return {
            "explanation": parsed.get("explanation", ""),
            "safety_tips": parsed.get("safety_tips", [])
        }
    except Exception as e:
        print(f"Gemini explain error: {e}")
        # Fallback — generate static but contextual tips
        return {
            "explanation": generate_fallback_explanation(content_type, risk_level, score, keywords),
            "safety_tips": generate_fallback_tips(content_type, risk_level, keywords)
        }


def generate_fallback_explanation(content_type, risk_level, score, keywords):
    if risk_level == "High":
        kw = keywords[:3] if keywords else ["suspicious patterns"]
        return (f"This {content_type} shows multiple high-risk indicators including {', '.join(kw)}. "
                f"The pattern matches known phishing tactics designed to create urgency and steal credentials. "
                f"Do not interact with any links or provide personal information.")
    elif risk_level == "Medium":
        return (f"This {content_type} contains some elements that warrant caution. "
                f"While not definitively malicious, the language and structure share similarities with phishing attempts. "
                f"Verify the sender through official channels before taking any action.")
    else:
        return (f"This {content_type} appears to be legitimate based on our analysis. "
                f"No significant phishing indicators were detected. "
                f"Always remain vigilant and verify unexpected communications through official channels.")


def generate_fallback_tips(content_type, risk_level, keywords):
    base_tips = [
        "Never click links in unsolicited messages — navigate directly to the official website instead.",
        "Legitimate organizations never ask for passwords, OTPs, or full card numbers via message.",
        "Check the sender's email domain carefully — phishers use lookalike domains (e.g. paypa1.com).",
        "Enable two-factor authentication on all important accounts as an extra safety layer.",
        "If you already clicked a suspicious link, change your passwords immediately and check your accounts."
    ]
    if "otp" in " ".join(keywords).lower() or "bank" in " ".join(keywords).lower():
        base_tips[0] = "Your bank will NEVER ask for your OTP, PIN, or full card number via SMS or email."
    if risk_level == "High":
        base_tips[4] = "⚠️ If you already interacted: change passwords immediately, contact your bank, and report to cybercrime.gov.in."
    return base_tips


def extract_text_from_image_gemini(img_b64: str, media_type: str) -> str:
    """Try Gemini Vision OCR."""
    model = genai.GenerativeModel(GEMINI_MODEL)
    image_part = {"mime_type": media_type, "data": base64.b64decode(img_b64)}
    response = model.generate_content([
        "Extract ALL visible text from this screenshot exactly as it appears. Return only the raw text, no commentary.",
        image_part
    ])
    return response.text.strip()


def extract_text_from_image_tesseract(img_b64: str) -> str:
    """Fallback: local pytesseract OCR (no quota)."""
    from PIL import Image
    import pytesseract
    img_bytes = base64.b64decode(img_b64)
    image = Image.open(io.BytesIO(img_bytes))
    return pytesseract.image_to_string(image).strip()


def extract_text_from_image(img_b64: str, media_type: str) -> str:
    """Try Gemini first, fall back to pytesseract."""
    try:
        return extract_text_from_image_gemini(img_b64, media_type)
    except Exception as e:
        print(f"⚠️  Gemini OCR failed ({e}), trying pytesseract...")
        try:
            return extract_text_from_image_tesseract(img_b64)
        except Exception as e2:
            raise HTTPException(status_code=500, detail=f"OCR failed: {str(e)} | Fallback: {str(e2)}")


# ── Core analysis ─────────────────────────────────────────────────────────────
def analyze_text(message: str) -> dict:
    text_lower = message.lower()

    # ML prediction
    ml_score = 50
    prediction = "Unknown"
    if ML_LOADED:
        try:
            vec = vectorizer.transform([message])
            pred = text_model.predict(vec)[0]
            prob = text_model.predict_proba(vec)[0]
            prediction = "Phishing" if pred == 1 else "Legitimate"
            ml_score = int(prob[1] * 100) if pred == 1 else int(prob[0] * 30)
        except Exception as e:
            print(f"ML error: {e}")

    # Keyword scoring
    found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in text_lower]
    keyword_score = min(len(found_keywords) * 8, 40)

    # URL suspicion in text
    suspicious_urls = re.findall(r'https?://[^\s]+', message)
    url_score = 0
    for url in suspicious_urls:
        if any(x in url for x in ['.tk', '.ml', '.cf', '.ga', 'bit.ly', 'tinyurl']):
            url_score += 20
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            url_score += 15

    final_score = min(ml_score + keyword_score + url_score, 100)

    if final_score >= 65:
        risk_level = "High"
    elif final_score >= 35:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # AI explanation
    ai_data = gemini_explain(message, "message", risk_level, final_score, found_keywords)

    return {
        "risk_level": risk_level,
        "score": final_score,
        "prediction": prediction,
        "keywords": found_keywords,
        "tactics": found_keywords,
        "explanation": ai_data["explanation"],
        "safety_tips": ai_data["safety_tips"]
    }


def score_url(url: str) -> dict:
    score = 0
    flags = []

    # Suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.cf', '.ga', '.gq', '.pw', '.cc', '.xyz', '.top', '.work']
    if any(url.endswith(t) or f"{t}/" in url for t in suspicious_tlds):
        score += 30
        flags.append("suspicious TLD")

    # IP address instead of domain
    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        score += 35
        flags.append("IP address URL")

    # URL shorteners
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'short.link', 'rebrand.ly']
    if any(s in url for s in shorteners):
        score += 20
        flags.append("URL shortener")

    # Typosquatting common brands
    brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix', 'facebook', 'instagram', 'sbi', 'hdfc', 'icici']
    domain = re.sub(r'https?://', '', url).split('/')[0]
    for brand in brands:
        if brand in domain and not domain.endswith(f".{brand}.com") and not domain == f"{brand}.com":
            score += 25
            flags.append(f"possible {brand} impersonation")
            break

    # Excessive subdomains
    if domain.count('.') > 3:
        score += 15
        flags.append("excessive subdomains")

    # Phishing keywords in URL
    url_keywords = ['login', 'verify', 'secure', 'update', 'confirm', 'account', 'password', 'signin', 'banking']
    for kw in url_keywords:
        if kw in url.lower():
            score += 10
            flags.append(f"keyword: {kw}")

    # HTTPS check
    if not url.startswith('https://'):
        score += 10
        flags.append("no HTTPS")

    score = min(score, 100)

    if score >= 65:
        risk_level = "High"
    elif score >= 35:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {"score": score, "risk_level": risk_level, "flags": flags}


# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "PhishNet API running", "version": "2.0"}

@app.get("/health")
def health():
    return {"status": "ok", "ml_loaded": ML_LOADED, "gemini": "configured"}


@app.post("/analyze-text")
async def analyze_text_endpoint(req: TextRequest):
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    return analyze_text(req.message)


@app.post("/analyze-url")
async def analyze_url_endpoint(req: URLRequest):
    if not req.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    url = req.url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    result = score_url(url)
    ai_data = gemini_explain(url, "URL", result["risk_level"], result["score"], result["flags"])

    return {
        "risk_level": result["risk_level"],
        "score": result["score"],
        "prediction": "Phishing" if result["score"] >= 65 else "Legitimate",
        "keywords": result["flags"],
        "tactics": result["flags"],
        "explanation": ai_data["explanation"],
        "safety_tips": ai_data["safety_tips"]
    }


@app.post("/analyze-screenshot")
async def analyze_screenshot(file: UploadFile = File(...)):
    contents = await file.read()
    img_b64 = base64.b64encode(contents).decode()

    # Fix media type
    media_type = file.content_type
    if not media_type or media_type == "application/octet-stream":
        ext = (file.filename or "").lower().split(".")[-1]
        media_type = {"png": "image/png", "jpg": "image/jpeg",
                      "jpeg": "image/jpeg", "webp": "image/webp"}.get(ext, "image/png")

    extracted_text = extract_text_from_image(img_b64, media_type)

    if not extracted_text.strip():
        extracted_text = "No readable text detected in image."

    analysis = analyze_text(extracted_text)

    return {
        "extracted_text": extracted_text,
        "analysis": analysis,
        "ocr_text": extracted_text   # backwards compat
    }