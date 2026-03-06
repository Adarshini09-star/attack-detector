# ml/train_url_model.py
"""
Train URL phishing detection model (feature-based).
Outputs:
  - ml/url_model.pkl
Usage:
  python ml/train_url_model.py
"""

import os
import re
import argparse
import pandas as pd
import numpy as np
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

SUSPICIOUS_KEYWORDS = ["login","verify","update","secure","account","bank","confirm","signin"]

def extract_features(url):
    """Return feature vector (dictionary) for a given url string."""
    u = url.strip()
    if not u:
        return None
    # ensure scheme
    if not re.match(r"^https?://", u):
        u = "http://" + u
    try:
        parsed = urlparse(u)
        hostname = parsed.netloc
        path = parsed.path
    except ValueError:
        # Handles malformed URLs such as invalid IPv6 addresses
        hostname = ""
        path = ""
    features = {}
    features["url_length"] = len(u)
    features["num_dots"] = hostname.count(".")
    features["has_at"] = 1 if "@" in u else 0
    features["has_ip"] = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", hostname) else 0
    features["has_https"] = 1 if u.startswith("https") else 0
    features["path_length"] = len(path)
    features["num_subdirs"] = path.count("/")
    features["hostname_len"] = len(hostname)
    features["suspicious_keyword"] = int(any(k in u.lower() for k in SUSPICIOUS_KEYWORDS))
    features["num_digits"] = sum(c.isdigit() for c in u)
    return features

def load_url_dataset(path="data/malicious_urls.csv"):
    # Expects columns: url,label
    df = pd.read_csv(path, encoding="latin-1", encoding_errors="replace")
    # Try to find columns
    cols = df.columns.tolist()
    url_col = next((c for c in cols if "url" in c.lower()), cols[0])
    label_col = next((c for c in cols if "label" in c.lower() or "class" in c.lower()), None)
    if label_col is None:
        # assume last column is label
        label_col = cols[-1]
    df = df[[url_col, label_col]].rename(columns={url_col:"url", label_col:"label"})
    # Map label to 0/1 if needed
    df["label"] = df["label"].apply(lambda v: 1 if str(v).strip().lower() in ("1","phishing","malicious","bad","true","yes") else 0)
    df = df.dropna(subset=["url"])
    return df

def build_features_df(df):
    rows = []
    for _, r in df.iterrows():
        feats = extract_features(r["url"])
        if feats is None:
            continue
        feats["label"] = r["label"]
        rows.append(feats)
    return pd.DataFrame(rows)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="data/malicious_urls.csv")
    parser.add_argument("--out", default="ml")
    args = parser.parse_args()
    df = load_url_dataset(args.data)
    print("Loaded URL dataset:", df.shape)
    X_df = build_features_df(df)
    X = X_df.drop(columns=["label"]).fillna(0).values
    y = X_df["label"].values
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    clf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, preds))
    print("Classification report:\n", classification_report(y_test, preds))
    joblib.dump(clf, os.path.join(args.out, "url_model.pkl"))
    print("Saved url_model.pkl to", args.out)

if __name__ == "__main__":
    main()