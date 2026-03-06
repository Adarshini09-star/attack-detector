import re
from urllib.parse import urlparse

PHISHING_KEYWORDS = [
    "login", "verify", "update", "secure", "banking", "account",
    "confirm", "paypal", "ebay", "amazon", "apple", "microsoft",
    "support", "password", "signin", "wallet", "free", "lucky",
    "winner", "claim", "urgent", "suspended", "alert", "netflix",
    "refund", "prize", "reward", "limited", "expire", "blocked"
]

SUSPICIOUS_TLDS = [".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw", ".cc"]

def extract_url_features(url: str) -> dict:
    features = {}
    parsed = urlparse(url)
    features["url_length"] = len(url)
    features["has_https"] = 1 if parsed.scheme == "https" else 0
    features["has_at_symbol"] = 1 if "@" in url else 0
    features["has_ip"] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_subdomains"] = max(len(parsed.netloc.split(".")) - 2, 0)
    features["has_phishing_keyword"] = 1 if any(k in url.lower() for k in PHISHING_KEYWORDS) else 0
    features["has_suspicious_tld"] = 1 if any(url.lower().endswith(t) or (t + "/") in url.lower() for t in SUSPICIOUS_TLDS) else 0
    features["has_double_slash"] = 1 if url.count("//") > 1 else 0
    features["path_length"] = len(parsed.path)
    features["has_query_params"] = 1 if parsed.query else 0
    return features

def score_url(url: str):
    f = extract_url_features(url)
    issues = []
    score = 0

    if f["url_length"] > 75:
        score += 15
        issues.append("unusually long URL")
    if not f["has_https"]:
        score += 20
        issues.append("no HTTPS — insecure connection")
    if f["has_at_symbol"]:
        score += 25
        issues.append("@ symbol used (browser redirect trick)")
    if f["has_ip"]:
        score += 30
        issues.append("IP address used instead of domain name")
    if f["num_dots"] > 4:
        score += 15
        issues.append("excessive subdomains")
    if f["num_hyphens"] > 3:
        score += 10
        issues.append("excessive hyphens in domain")
    if f["has_phishing_keyword"]:
        score += 25
        issues.append("phishing keywords detected in URL")
    if f["has_suspicious_tld"]:
        score += 25
        issues.append("suspicious top-level domain (.ru, .tk, .xyz, etc.)")
    if f["has_double_slash"]:
        score += 10
        issues.append("double slash redirect trick in path")

    score = min(score, 100)

    if score >= 60:
        risk_level = "High"
        prediction = "Phishing URL"
    elif score >= 30:
        risk_level = "Medium"
        prediction = "Suspicious URL"
    else:
        risk_level = "Low"
        prediction = "Likely Safe"

    return {
        "risk_level": risk_level,
        "score": score,
        "prediction": prediction,
        "issues": issues if issues else ["No major issues detected"]
    }