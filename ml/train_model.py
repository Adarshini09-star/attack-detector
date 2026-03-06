"""
ml/train_model.py
Trains on real SMS spam dataset + synthetic Indian bank/phishing samples.
Key fix: legitimate bank transaction patterns are labelled as ham (0).
"""

import pickle, re, pathlib
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix

HERE = pathlib.Path(__file__).parent

# ── Load SMS spam dataset ─────────────────────
df = pd.read_csv(HERE.parent / "data.csv",
                 sep="\t", header=None, names=["label", "text"],
                 encoding="latin-1", on_bad_lines="skip")

df["label"] = df["label"].map({"ham": 0, "spam": 1})
df = df.dropna(subset=["label", "text"])
df["label"] = df["label"].astype(int)

print(f"Loaded {len(df)} SMS rows  |  spam: {df.label.sum()}  ham: {(df.label==0).sum()}")

# ── Synthetic samples: Indian banking (ham=0) ─
INDIAN_BANK_HAM = [
    ("Rs.500.00 debited from A/c XX1234 on 01-03-25. Info: UPI/VPA paytmqr@paytm. Avl Bal Rs.12450.00.", 0),
    ("Dear Customer, Rs 299 has been debited from your HDFC Bank account ending 4321 for UPI transaction. UPI Ref 119584071212.", 0),
    ("Your ICICI Bank A/c XX7890 is credited with Rs.5000.00 on 02-Mar-25 by NEFT. Avl Bal: Rs.28,350.00.", 0),
    ("242315 is your OTP for HDFC Bank NetBanking login. Valid for 10 minutes. Do NOT share with anyone.", 0),
    ("873421 is your SBI OTP for UPI transaction of Rs.199. Valid 5 mins. Do not share.", 0),
    ("Txn of Rs.1200 done on SBI Debit Card XX5678 at AMAZON on 02-03-25. Avl Bal Rs.8200.", 0),
    ("Dear Customer, your Axis Bank A/c XX3456 is debited Rs.750 on 03/03/25. UPI Ref: 4839201.", 0),
    ("Your Kotak Bank A/c is credited with Rs.10000 by IMPS from RAHUL SHARMA on 01-Mar-25.", 0),
    ("PhonePe: Rs.300 paid to SWIGGY successfully. UPI Ref No 384920192. 01 Mar 2025 18:42.", 0),
    ("Paytm: Rs.99 debited for Paytm Postpaid bill. Txn ID T2025030198234. Avl Limit: Rs.4901.", 0),
    ("Your Yes Bank A/c XX2345 is credited Rs.25000 salary on 28-Feb-25. Avl Bal: Rs.31,200.", 0),
    ("HDFC Bank: Rs.45.00 debited from A/c XX6789 at McDonald's on 02-Mar-25 09:14. Avl Bal Rs.6234.", 0),
    ("GPay: Payment of Rs.150 to Reliance Fresh successful. Google Pay Ref 29384756.", 0),
    ("Dear Customer, Rs.500 debited from SBI A/c XX8901 via UPI to PhonePe on 01-Mar-25 18:30.", 0),
    ("IRCTC: Booking confirmed. PNR 4728394756. Train 12658. Seat B2/34. Journey 05-Mar-25.", 0),
    ("Flipkart: Your order #FK293847 is out for delivery. Expected by 5 PM today.", 0),
    ("Amazon: Your order for realme Buds has been shipped. Delivery by 04-Mar-25.", 0),
    ("Zomato order #Z98234 confirmed. Delivery in 35-40 mins. Track here: zomato.com/track", 0),
    ("HDFC Bank: Your credit card XX1234 bill of Rs.8450 is due on 10-Mar. Pay now to avoid charges.", 0),
    ("Swiggy: Your order has arrived! Rate your experience.", 0),
    ("Dear Customer, your Canara Bank A/c has been credited Rs.15000 by NEFT on 28-Feb-25.", 0),
    ("PNB: Rs.2000 ATM withdrawal from A/c XX3456 on 02-Mar-25 at 14:32. Avl Bal Rs.5,200.", 0),
    ("Union Bank: OTP 647291 for NEFT transfer of Rs.5000. Valid 5 mins. Never share OTP.", 0),
    ("IndusInd Bank: A/c XX9012 debited Rs.1500 on 01-Mar-25 via IMPS. Ref 748291038.", 0),
    ("UIDAI: Your Aadhaar eKYC has been authenticated successfully for service.", 0),
]

# ── Synthetic samples: Indian phishing (spam=1) ─
INDIAN_PHISHING_SPAM = [
    ("URGENT: Your HDFC Bank account has been temporarily blocked. Click here to verify: hdfcbank-verify.tk/login", 1),
    ("Congratulations! You won Rs.50,000 in SBI Lucky Draw. Click to claim: sbi-prize.ml/claim", 1),
    ("Your KYC is incomplete. Your bank account will be BLOCKED in 24 hours. Update now: kyc-update.xyz", 1),
    ("ALERT: Suspicious login on your PayTM wallet. Verify identity immediately: paytm-secure.ru/verify", 1),
    ("Dear Customer, your ICICI account is suspended. Call 9876543210 immediately to avoid legal action.", 1),
    ("You have won Rs.2 Lakh in Google India Lottery. Send your bank details to claim prize.", 1),
    ("Income Tax Dept: Refund of Rs.15000 approved. Verify PAN and bank: incometax-refund.tk", 1),
    ("FREE: Work from home and earn Rs.50,000/month. No investment needed. WhatsApp 9988776655 now!", 1),
    ("Your Aadhaar card has been linked to a criminal case. Call 8899001122 to clear your name.", 1),
    ("TRAI will disconnect your mobile in 2 hours. Press 1 immediately to prevent disconnection.", 1),
    ("Congratulations! Your number selected for PM Kisan Yojana Rs.6000. Share bank details to receive.", 1),
    ("Mumbai Police: FIR registered against your number. Call 7788990011 to know more and avoid arrest.", 1),
    ("Your electricity connection will be cut tonight. Pay Rs.300 now: electricity-pay.xyz/bill", 1),
    ("Amazon India: You won a Samsung TV in our anniversary sale. Click to claim: amazon-prize.gq", 1),
    ("URGENT: Your EPF account password expired. Update now or lose access: epfo-update.ml/login", 1),
    ("Your credit card has been charged Rs.49,999 by unknown party. Call 9900112233 to dispute NOW.", 1),
    ("RBI special scheme: Get Rs.25,000 loan in 10 mins. No documents. Share Aadhaar and bank details.", 1),
    ("Your SIM will be blocked in 2 hours. KYC update required. Call 8877665544 immediately.", 1),
    ("Crypto investment opportunity: Turn Rs.1000 into Rs.50,000 in 7 days. Join now: crypto-india.ru", 1),
    ("WhatsApp is expiring! Share this message to 10 people or your account will be deactivated.", 1),
]

synth_df = pd.DataFrame(INDIAN_BANK_HAM + INDIAN_PHISHING_SPAM, columns=["text", "label"])
df = pd.concat([df, synth_df], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
print(f"After augmentation: {len(df)} total  |  spam: {df.label.sum()}  ham: {(df.label==0).sum()}")

# ── Preprocessing ─────────────────────────────
def preprocess(text):
    t = str(text).lower()
    t = re.sub(r'http\S+|www\S+', ' URL ', t)
    t = re.sub(r'\d{10,}', ' LONGNUM ', t)     # phone numbers → token
    t = re.sub(r'rs\.?\s*\d[\d,]*(\.\d+)?', ' INRAMOUNT ', t, flags=re.I)  # Rs amounts → token
    t = re.sub(r'\d{4,8}', ' OTP ', t)          # 4-8 digit codes → OTP token
    t = re.sub(r'[^a-z\s]', ' ', t)
    t = re.sub(r'\s+', ' ', t).strip()
    return t

df["clean"] = df["text"].apply(preprocess)

# ── Train/test split ──────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    df["clean"], df["label"], test_size=0.15, random_state=42, stratify=df["label"]
)

# ── Vectorizer ────────────────────────────────
vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=8000,
    min_df=2,
    sublinear_tf=True
)
X_tr = vectorizer.fit_transform(X_train)
X_te = vectorizer.transform(X_test)

# ── Model ─────────────────────────────────────
# class_weight='balanced' prevents the model from being biased toward ham
model = LogisticRegression(max_iter=2000, C=2.0, class_weight="balanced", solver="lbfgs")
model.fit(X_tr, y_train)

# ── Evaluate ──────────────────────────────────
y_pred = model.predict(X_te)
print("\n── Model Evaluation ──")
print(classification_report(y_test, y_pred, target_names=["Ham (Safe)", "Spam (Phishing)"]))
print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))

cv = cross_val_score(model, vectorizer.transform(df["clean"]), df["label"], cv=5, scoring="f1")
print(f"5-fold F1 scores: {cv.round(3)}  →  mean {cv.mean():.3f}")

# ── Quick sanity checks ───────────────────────
print("\n── Sanity checks ──")
tests = [
    ("Rs.500 debited from HDFC A/c XX1234 via UPI. UPI Ref 119584071212.", "EXPECT: Low"),
    ("873421 is your SBI OTP for UPI. Valid 5 mins. Do not share.", "EXPECT: Low"),
    ("Your account will be BLOCKED. Click here to verify: hdfc-secure.tk/login", "EXPECT: High"),
    ("Congratulations! You won Rs.50000 in SBI Lucky Draw. Claim now!", "EXPECT: High"),
    ("The meeting is at 3 PM tomorrow.", "EXPECT: Low"),
]
for txt, expect in tests:
    v = vectorizer.transform([preprocess(txt)])
    prob = model.predict_proba(v)[0][1]
    print(f"  [{expect}]  prob={prob:.2f}  →  {'Spam' if prob>0.5 else 'Ham'}  |  {txt[:60]}...")

# ── Save ──────────────────────────────────────
with open(HERE / "text_model.pkl", "wb") as f:
    pickle.dump(model, f)
with open(HERE / "vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)
# Save the preprocess function too so backend can use it
import json
with open(HERE / "label_map.json", "w") as f:
    json.dump({"0": "Safe", "1": "SocialEngineering"}, f)

print(f"\n✅ Saved ml/text_model.pkl + ml/vectorizer.pkl")
