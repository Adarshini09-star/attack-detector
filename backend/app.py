"""
PhishNet API
ML + Rule-based + Claude AI + Screenshot OCR
"""

import os
import re
import time
import base64
import pickle
import pathlib
from typing import List, Optional

from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel


# ================================
# Claude AI Setup
# ================================

try:
    import anthropic

    _ai_client = anthropic.Anthropic(
        api_key=os.environ.get("ANTHROPIC_API_KEY", "")
    )

    _AI_AVAILABLE = bool(os.environ.get("ANTHROPIC_API_KEY"))

except Exception:
    _ai_client = None
    _AI_AVAILABLE = False


# ================================
# Load ML Models
# ================================

ROOT = pathlib.Path(__file__).parent.parent


def load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)


try:
    TEXT_MODEL = load_pickle(ROOT / "ml" / "text_model.pkl")
    VECTORIZER = load_pickle(ROOT / "ml" / "vectorizer.pkl")
    ML_READY = True
    print("ML model loaded")

except Exception as e:
    TEXT_MODEL = None
    VECTORIZER = None
    ML_READY = False
    print("ML model not found:", e)


# ================================
# FastAPI Setup
# ================================

app = FastAPI(title="PhishNet API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

try:
    app.mount("/app", StaticFiles(directory=str(ROOT / "frontend"), html=True))
except:
    pass


# ================================
# Request Schemas
# ================================

class TextRequest(BaseModel):
    message: str
    lang: str = "en"
    use_ai: bool = True


class URLRequest(BaseModel):
    url: str
    lang: str = "en"
    use_ai: bool = True


# ================================
# Utility Functions
# ================================

def risk_bucket(score):

    if score >= 60:
        return "High"

    if score >= 35:
        return "Medium"

    return "Low"


# ================================
# Claude Vision OCR
# ================================

def ai_extract_text(img_b64, media_type):

    if not _AI_AVAILABLE:
        raise HTTPException(503, "Claude AI not available")

    resp = _ai_client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        messages=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": media_type,
                            "data": img_b64
                        }
                    },
                    {
                        "type": "text",
                        "text": "Extract all visible text from this screenshot exactly as written."
                    }
                ]
            }
        ]
    )

    return resp.content[0].text.strip()


# ================================
# Root
# ================================

@app.get("/")
def root():

    return {
        "status": "PhishNet API running",
        "ml_ready": ML_READY,
        "ai_ready": _AI_AVAILABLE
    }


# ================================
# TEXT ANALYSIS
# ================================

@app.post("/analyze-text")
def analyze_text(req: TextRequest):

    msg = req.message.strip()

    if not msg:
        raise HTTPException(400, "Message cannot be empty")

    # ML prediction
    ml_score = 50
    ml_label = "Unknown"

    if ML_READY:

        vec = VECTORIZER.transform([msg])

        prob = TEXT_MODEL.predict_proba(vec)[0][1]

        ml_score = round(prob * 100, 1)

        ml_label = "Social Engineering" if prob >= 0.5 else "Legitimate"

    # Rule checks
    signals = []

    if re.search(r'urgent|immediately|act now', msg, re.I):
        signals.append("Urgency Pressure")

    if re.search(r'click here|verify|login|update account', msg, re.I):
        signals.append("Credential Harvesting")

    if re.search(r'won|lottery|prize', msg, re.I):
        signals.append("Prize Scam")

    rule_score = len(signals) * 10

    final_score = min(round(ml_score * 0.6 + rule_score), 100)

    risk = risk_bucket(final_score)

    explanation = "This message contains patterns associated with phishing."

    if req.use_ai and _AI_AVAILABLE:

        ai_prompt = f"""
Explain in 2 sentences why this message may be phishing:

{msg}
"""

        try:

            resp = _ai_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=200,
                messages=[{"role": "user", "content": ai_prompt}]
            )

            explanation = resp.content[0].text.strip()

        except:
            pass

    return {
        "risk_level": risk,
        "score": final_score,
        "prediction": ml_label,
        "signals": signals,
        "ml_score": ml_score,
        "explanation": explanation
    }


# ================================
# URL ANALYSIS
# ================================

@app.post("/analyze-url")
def analyze_url(req: URLRequest):

    url = req.url.strip()

    if not url:
        raise HTTPException(400, "URL cannot be empty")

    score = 0
    issues = []

    if len(url) > 70:
        score += 20
        issues.append("Long URL")

    if "@" in url:
        score += 25
        issues.append("Contains @ symbol")

    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        score += 30
        issues.append("IP address in URL")

    if re.search(r'login|verify|secure|account', url, re.I):
        score += 15
        issues.append("Suspicious keywords")

    score = min(score, 100)

    risk = risk_bucket(score)

    return {
        "risk_level": risk,
        "score": score,
        "issues": issues
    }


# ================================
# SCREENSHOT ANALYSIS
# ================================

@app.post("/analyze-screenshot")
async def analyze_screenshot(file: UploadFile = File(...)):

    start = time.time()

    contents = await file.read()

    media_type = file.content_type or "image/jpeg"

    img_b64 = base64.b64encode(contents).decode("utf-8")

    try:

        extracted_text = ai_extract_text(img_b64, media_type)

    except Exception as e:

        raise HTTPException(500, f"OCR failed: {str(e)}")

    if not extracted_text:

        return {
            "risk_level": "Low",
            "score": 0,
            "extracted_text": "",
            "explanation": "No text found in screenshot"
        }

    result = analyze_text(TextRequest(message=extracted_text))

    elapsed = round((time.time() - start) * 1000)

    return {
        "extracted_text": extracted_text,
        "analysis": result,
        "elapsed_ms": elapsed
    }


# ================================
# OCR ONLY
# ================================

@app.post("/ocr")
async def ocr(file: UploadFile = File(...)):

    contents = await file.read()

    media_type = file.content_type or "image/jpeg"

    img_b64 = base64.b64encode(contents).decode("utf-8")

    text = ai_extract_text(img_b64, media_type)

    return {
        "text": text,
        "char_count": len(text)
    }