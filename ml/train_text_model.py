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