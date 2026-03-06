# PhishNet — AI Phishing Detector

## Project Structure
```
phishnet/
├── backend/
│   ├── app.py           ← FastAPI server (ML + Rules + Claude AI)
│   ├── .env             ← ANTHROPIC_API_KEY goes here
│   └── requirements.txt
├── ml/
│   ├── text_model.pkl   ← Trained classifier (sms_spam + curated examples)
│   ├── vectorizer.pkl   ← TF-IDF vectorizer
│   └── train_text_model.py ← Retrain script
├── url_detection/
│   └── url_features.py  ← Rule-based URL scorer
├── frontend/
│   └── index.html       ← Web dashboard (served at /app)
├── extension/           ← Chrome/Edge extension
│   ├── manifest.json
│   ├── content.js       ← Auto-scans Gmail & WhatsApp
│   ├── detection_engine.js ← Smart local detection
│   ├── popup.html / popup.js
│   └── background.js
├── start.bat            ← Windows startup script
└── start.sh             ← Linux/Mac startup script
```

## Setup

### 1. Add API Key
Edit `backend/.env`:
```
ANTHROPIC_API_KEY=sk-ant-...your-key-here...
```

### 2. Start Backend
**Windows:** Double-click `start.bat`  
**Mac/Linux:** `bash start.sh`

Backend runs at: http://localhost:8000  
Web dashboard: http://localhost:8000/app  
API docs: http://localhost:8000/docs

### 3. Install Extension
1. Open Edge: `edge://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked" → select the `extension/` folder
4. Add your API key in `extension/popup.js` line 6 and `extension/content.js` line 6

## How Detection Works

| Layer | What it does |
|-------|-------------|
| **Rules (instant)** | Detects legitimate bank patterns (UPI, OTP, NEFT) → marks Safe |
| **Rules (instant)** | Detects strong phishing signals → marks High Risk immediately |
| **ML Model** | TF-IDF + Logistic Regression trained on 5,200+ messages |
| **Claude AI** | Generates human-readable explanation in English/Hindi/Kannada |

### Why bank messages are NOT flagged
- ML model was retrained with 150+ real UPI/OTP/NEFT messages (oversampled 6x)
- Rule layer caps score to ≤27% for messages matching bank transaction patterns
- Claude's prompt explicitly instructs it to treat transaction alerts as legitimate

## Retrain Model
If you get the phishing emails CSV later:
```bash
python ml/train_text_model.py data/sms_spam.csv
```
