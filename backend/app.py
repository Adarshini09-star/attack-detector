import os
import re
import base64
import pickle
import pathlib

from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import google.generativeai as genai


# ================================
# PASTE YOUR GEMINI API KEY HERE
# Get it free at: aistudio.google.com
# ================================

GEMINI_API_KEY = "AIzaSyBSUpAmpOON8J2RYWjtJnHeNDGbKzRfT1A"

genai.configure(api_key=GEMINI_API_KEY)
AI_AVAILABLE = True


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
# FastAPI setup
# ================================

app = FastAPI(title="PhishNet API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

try:
    app.mount("/app", StaticFiles(directory=str(ROOT / "frontend"), html=True))
except Exception as e:
    print("Static files not mounted:", e)


# ================================
# Request schemas
# ================================

class TextRequest(BaseModel):
    message: str


class URLRequest(BaseModel):
    url: str


# ================================
# Gemini OCR — extracts text from image
# ================================

def extract_text_from_image(img_b64: str, media_type: str) -> str:
    """Use Gemini Flash (free) to OCR a screenshot and return all visible text."""
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")

        image_part = {
            "mime_type": media_type,
            "data": base64.b64decode(img_b64)
        }

        response = model.generate_content([
            "Extract all visible text from this screenshot. Return only the raw text, no commentary.",
            image_part
        ])

        return response.text.strip()

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OCR failed: {str(e)}")


# ================================
# Health check
# ================================

@app.get("/health")
def health():
    return {
        "ml": ML_READY,
        "ai": AI_AVAILABLE
    }


# ================================
# Suspicious keyword detection
# ================================

SUSPICIOUS_WORDS = [
    "urgent", "verify", "account", "password", "otp",
    "click", "login", "bank", "suspended", "prize", "lottery"
]


def detect_keywords(text: str) -> list:
    found = []
    for w in SUSPICIOUS_WORDS:
        if re.search(rf"\b{w}\b", text, re.I):
            found.append(w)
    return found


# ================================
# Text analysis
# ================================

@app.post("/analyze-text")
def analyze_text(req: TextRequest):

    msg = req.message.strip()

    if not msg:
        raise HTTPException(400, "Empty message")

    ml_score = 50

    if ML_READY:
        vec = VECTORIZER.transform([msg])
        prob = TEXT_MODEL.predict_proba(vec)[0][1]
        ml_score = round(prob * 100)

    keywords = detect_keywords(msg)
    rule_score = len(keywords) * 10
    final_score = min(int(ml_score * 0.6 + rule_score), 100)

    if final_score >= 60:
        risk = "High"
    elif final_score >= 35:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "risk_level": risk,
        "score": final_score,
        "keywords": keywords,
        "threat_type": "Social Engineering" if final_score >= 50 else "Likely Safe",
        "confidence": ml_score,
        "signals": keywords,
        "analysis_summary": f"Detected {len(keywords)} suspicious indicators commonly used in phishing attacks."
    }


# ================================
# URL analysis
# ================================

@app.post("/analyze-url")
def analyze_url(req: URLRequest):

    url = req.url
    score = 0
    issues = []

    if "@" in url:
        score += 25
        issues.append("Suspicious @ symbol")

    if len(url) > 70:
        score += 20
        issues.append("Very long URL")

    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        score += 30
        issues.append("IP address used")

    if re.search(r'login|verify|secure|bank', url, re.I):
        score += 20
        issues.append("Phishing keywords")

    score = min(score, 100)

    if score >= 60:
        risk = "High"
    elif score >= 35:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "risk_level": risk,
        "score": score,
        "issues": issues
    }


# ================================
# Screenshot analysis
# ================================

@app.post("/analyze-screenshot")
async def analyze_screenshot(file: UploadFile = File(...)):

    contents = await file.read()
    img_b64 = base64.b64encode(contents).decode()

    # Fix missing or generic media type
    media_type = file.content_type
    if not media_type or media_type == "application/octet-stream":
        ext = file.filename.lower().split(".")[-1]
        media_type = {
            "png": "image/png",
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "webp": "image/webp"
        }.get(ext, "image/png")

    # OCR via Gemini
    text = extract_text_from_image(img_b64, media_type)

    # Run phishing analysis on extracted text
    result = analyze_text(TextRequest(message=text))

    return {
        "extracted_text": text,
        "analysis": result
    }