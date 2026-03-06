<<<<<<< HEAD
"""
ml/train_text_model.py
Run once to train and save the text classification model.
Usage: python ml/train_text_model.py
"""

import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# ── TRAINING DATA ─────────────────────────────────────────
# Label 1 = Social Engineering / Phishing, 0 = Legitimate
SAMPLES = [
    # PHISHING / SOCIAL ENGINEERING (label=1)
    ("URGENT: Your bank account will be suspended. Verify immediately.", 1),
    ("Congratulations! You've won a $1000 Amazon gift card. Claim now!", 1),
    ("Your password has been compromised. Click here to reset immediately.", 1),
    ("ALERT: Unauthorized login detected on your account. Act now!", 1),
    ("Your package is on hold. Pay $2.99 customs fee to release it.", 1),
    ("Dear customer, your Netflix subscription has expired. Update payment.", 1),
    ("IRS Notice: You owe back taxes. Pay now to avoid arrest.", 1),
    ("Your Apple ID has been locked. Verify your information immediately.", 1),
    ("WINNER! You have been selected for a free iPhone. Click to claim.", 1),
    ("Security Alert: Someone accessed your Gmail. Confirm your identity.", 1),
    ("Final warning: Your account will be closed in 24 hours.", 1),
    ("Urgent: Verify your PayPal account or it will be permanently limited.", 1),
    ("Dear user, your Microsoft account is at risk. Update credentials now.", 1),
    ("You owe $500 in unpaid tolls. Pay within 24 hours to avoid penalty.", 1),
    ("Suspicious activity detected. Call us immediately at this number.", 1),
    ("Your Social Security Number has been suspended. Contact us now.", 1),
    ("Congratulations, you qualify for a government COVID relief grant.", 1),
    ("Action required: Confirm your email or lose access to your account.", 1),
    ("LAST CHANCE: Your subscription expires tonight. Renew to keep access.", 1),
    ("Warning: Your computer has a virus. Call Microsoft support now.", 1),
    ("Your bank transfer requires additional verification. Click here.", 1),
    ("Hi, I'm a Nigerian prince. I need your help transferring funds.", 1),
    ("You have unclaimed lottery winnings. Send ID to receive funds.", 1),
    ("Your Uber account has been hacked. Reset password immediately.", 1),
    ("ALERT: Your credit card was charged $499. Dispute at this link.", 1),
    ("Limited time offer: Work from home and earn $5000/week guaranteed.", 1),
    ("Your insurance claim needs review. Call now or lose your coverage.", 1),
    ("Verify your identity within 48 hours or your account will be deleted.", 1),
    ("Dear winner, claim your prize before it expires at midnight!", 1),
    ("Your loan has been approved. Send processing fee to receive funds.", 1),

    # LEGITIMATE (label=0)
    ("Hi! Just wanted to check in and see how you're doing.", 0),
    ("The meeting is scheduled for tomorrow at 3 PM.", 0),
    ("Please find attached the report you requested.", 0),
    ("Your order has shipped and will arrive in 3-5 business days.", 0),
    ("Thank you for your purchase. Your receipt is attached.", 0),
    ("Reminder: Team standup at 9 AM tomorrow.", 0),
    ("Here is the summary of our discussion from today.", 0),
    ("Happy birthday! Hope you have a wonderful day.", 0),
    ("The project deadline has been extended to next Friday.", 0),
    ("Please review the document and share your feedback.", 0),
    ("Your appointment is confirmed for Monday at 2 PM.", 0),
    ("Great job on the presentation! The client loved it.", 0),
    ("The quarterly report is ready for your review.", 0),
    ("Let's catch up over coffee sometime this week.", 0),
    ("Your subscription has been renewed successfully.", 0),
    ("Here are the minutes from our last team meeting.", 0),
    ("The new feature has been deployed to production.", 0),
    ("Thanks for joining us at the event yesterday.", 0),
    ("Your feedback has been submitted. We'll review it shortly.", 0),
    ("Lunch today at noon — are you free to join?", 0),
    ("I've updated the spreadsheet with the latest numbers.", 0),
    ("The library book you reserved is now available for pickup.", 0),
    ("Your flight has been confirmed. Check-in opens 24 hours before.", 0),
    ("We've received your application and will be in touch.", 0),
    ("Monthly newsletter: Updates from our team this month.", 0),
    ("The wifi password for the conference room is posted on the board.", 0),
    ("Your package from Amazon was delivered to your front door.", 0),
    ("Just a reminder to submit your timesheet by end of day Friday.", 0),
    ("The gym is closed for maintenance this Saturday.", 0),
    ("Here's the link to the shared Google Doc we discussed.", 0),
]

texts  = [s[0] for s in SAMPLES]
labels = [s[1] for s in SAMPLES]

# ── TRAIN ─────────────────────────────────────────────────
vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=5000,
    stop_words='english'
)

X = vectorizer.fit_transform(texts)
y = np.array(labels)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = LogisticRegression(max_iter=1000, C=1.0)
model.fit(X_train, y_train)

# ── EVALUATE ──────────────────────────────────────────────
y_pred = model.predict(X_test)
print("\n── Text Model Evaluation ──")
print(classification_report(y_test, y_pred, target_names=["Legitimate", "Social Engineering"]))

# ── SAVE ──────────────────────────────────────────────────
with open("ml/text_model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("ml/vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)

print("✅ Saved: ml/text_model.pkl")
print("✅ Saved: ml/vectorizer.pkl")
=======
# ml/train_text_model.py
"""
Train text classifier for Social Engineering detection.
Outputs:
  - ml/text_model.pkl
  - ml/vectorizer.pkl
  - ml/label_map.json (optional)
Usage:
  python ml/train_text_model.py
"""

import os
import re
import json
import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import nltk
from nltk.corpus import stopwords

# Ensure nltk stopwords are available
nltk.download("stopwords", quiet=True)

def clean_text(s):
    if not isinstance(s, str):
        return ""
    s = s.lower()
    s = re.sub(r"http\S+", " ", s)           # remove URLs
    s = re.sub(r"\S+@\S+", " ", s)           # remove emails
    s = re.sub(r"[^a-z0-9\s]", " ", s)       # keep alphanumerics and spaces
    s = re.sub(r"\s+", " ", s).strip()
    return s

def load_and_merge(sms_path=None, phishing_path=None, extra_csvs=None):
    # Expect CSVs with text and label-like columns; adapt if different
    frames = []
    if sms_path and Path(sms_path).exists():
        on_bad_lines="skip"
        df = pd.read_csv(sms_path, sep="\t", encoding="latin-1",
                 names=["label","text"], on_bad_lines="skip")
        # UCI sms dataset has columns: v1(label) and v2(message)
        if "v1" in df.columns and "v2" in df.columns:
            df = df.rename(columns={"v1":"label", "v2":"text"})
        # Map ham->0 spam->1
        df["label"] = df["label"].map(lambda x: 1 if str(x).strip().lower() in ("spam","1","phishing") else 0)
        frames.append(df[["text","label"]])
    if phishing_path and Path(phishing_path).exists():
        df = pd.read_csv(phishing_path, encoding="latin-1")
        # If dataset has a column named 'Email Text' or 'text'
        possible_text_cols = ["text","message","email","Email Text","Email"]
        text_col = next((c for c in df.columns if c in possible_text_cols), None)
        # If there is a label column
        label_col = next((c for c in df.columns if "label" in c.lower() or "type" in c.lower()), None)
        if text_col is None:
            # try the first text-like column
            text_col = df.columns[0]
        if label_col is None:
            # assume phishing dataset contains only phishing examples -> label=1
            df = df.assign(label=1)
            frames.append(df[[text_col, "label"]].rename(columns={text_col:"text"}))
        else:
            frames.append(df[[text_col, label_col]].rename(columns={text_col:"text", label_col:"label"}))
    if extra_csvs:
        for p in extra_csvs:
            if Path(p).exists():
                df = pd.read_csv(p, encoding="latin-1", encoding_errors="replace")
                # try to find text & label columns
                cols = df.columns.tolist()
                text_col = next((c for c in cols if "text" in c.lower() or "message" in c.lower()), cols[0])
                label_col = next((c for c in cols if "label" in c.lower() or "type" in c.lower()), None)
                if label_col is None:
                    df["label"] = 1
                    frames.append(df[[text_col,"label"]].rename(columns={text_col:"text"}))
                else:
                    frames.append(df[[text_col,label_col]].rename(columns={text_col:"text", label_col:"label"}))
    if not frames:
        raise ValueError("No datasets loaded. Check paths.")
    combined = pd.concat(frames, ignore_index=True)
    combined["text"] = combined["text"].astype(str)
    combined["text"] = combined["text"].apply(clean_text)
    # Standardize labels to 0/1
    def map_label(v):
        try:
            v = str(v).strip().lower()
            if v in ("ham","safe","normal","0","none","legit"):
                return 0
            if v in ("spam","phishing","scam","1","attack","malicious"):
                return 1
            # fallback: if numeric
            if v.isdigit():
                return int(v) if int(v) in (0,1) else 1
        except:
            pass
        return 1 if v else 0
    combined["label"] = combined["label"].apply(map_label)
    # Drop empty texts
    combined = combined[combined["text"].str.strip() != ""]
    combined = combined.reset_index(drop=True)
    return combined

def build_and_train(df, output_dir="ml", test_size=0.2, random_state=42):
    X = df["text"].values
    y = df["label"].values
    # vectorizer
    vectorizer = TfidfVectorizer(stop_words=stopwords.words("english"), max_features=5000, ngram_range=(1,2))
    X_vec = vectorizer.fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=test_size, random_state=random_state, stratify=y)
    # classifier (fast + explainable)
    clf = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=random_state)
    clf.fit(X_train, y_train)
    # eval
    preds = clf.predict(X_test)
    proba = clf.predict_proba(X_test)[:,1]
    acc = accuracy_score(y_test, preds)
    print("Test accuracy:", acc)
    print("Classification report:\n", classification_report(y_test, preds))
    print("Confusion matrix:\n", confusion_matrix(y_test, preds))
    # Save
    os.makedirs(output_dir, exist_ok=True)
    joblib.dump(clf, os.path.join(output_dir, "text_model.pkl"))
    joblib.dump(vectorizer, os.path.join(output_dir, "vectorizer.pkl"))
    # label map
    label_map = {0:"Safe", 1:"SocialEngineering"}
    with open(os.path.join(output_dir, "label_map.json"), "w") as f:
        json.dump(label_map, f)
    print("Saved model and vectorizer to", output_dir)
    return clf, vectorizer

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sms", default="data/sms_spam.csv")
    parser.add_argument("--phishing", default="data/phishing_emails.csv")
    parser.add_argument("--extra", nargs="*", default=None)
    parser.add_argument("--out", default="ml")
    args = parser.parse_args()
    df = load_and_merge(args.sms, args.phishing, args.extra)
    print("Loaded dataset shape:", df.shape)
    # Optional: quick class balance info
    print(df["label"].value_counts())
    build_and_train(df, output_dir=args.out)

if __name__ == "__main__":
    main()
>>>>>>> 8369deca717525406924c8eef345cb5ced6a25ed
