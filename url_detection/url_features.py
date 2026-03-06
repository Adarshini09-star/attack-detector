import re
from urllib.parse import urlparse

PHISHING_KEYWORDS = [
    "login","verify","update","secure","banking","account","confirm","paypal",
    "ebay","amazon","apple","microsoft","support","password","signin","wallet",
    "free","lucky","winner","claim","urgent","suspended","alert","netflix",
    "refund","prize","reward","limited","expire","blocked","kyc","otp"
]
SUSPICIOUS_TLDS = [".ru",".cn",".tk",".ml",".ga",".cf",".gq",".xyz",".top",".pw",".cc"]

def extract_url_features(url: str) -> dict:
    parsed = urlparse(url)
    return {
        "url_length":           len(url),
        "has_https":            1 if parsed.scheme=="https" else 0,
        "has_at_symbol":        1 if "@" in url else 0,
        "has_ip":               1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0,
        "num_dots":             url.count("."),
        "num_hyphens":          url.count("-"),
        "num_subdomains":       max(len(parsed.netloc.split("."))-2, 0),
        "has_phishing_keyword": 1 if any(k in url.lower() for k in PHISHING_KEYWORDS) else 0,
        "has_suspicious_tld":   1 if any(url.lower().endswith(t) or (t+"/") in url.lower() for t in SUSPICIOUS_TLDS) else 0,
        "has_double_slash":     1 if url.count("//")>1 else 0,
        "path_length":          len(parsed.path),
        "has_query_params":     1 if parsed.query else 0,
    }

def score_url(url: str):
    f = extract_url_features(url)
    issues, score = [], 0
    if f["url_length"] > 75:      score+=15; issues.append("Unusually long URL")
    if not f["has_https"]:         score+=20; issues.append("No HTTPS — insecure connection")
    if f["has_at_symbol"]:         score+=25; issues.append("@ symbol (browser redirect trick)")
    if f["has_ip"]:                score+=30; issues.append("IP address instead of domain name")
    if f["num_dots"] > 4:          score+=15; issues.append("Excessive subdomains")
    if f["num_hyphens"] > 3:       score+=10; issues.append("Excessive hyphens in domain")
    if f["has_phishing_keyword"]:  score+=25; issues.append("Phishing keywords detected in URL")
    if f["has_suspicious_tld"]:    score+=25; issues.append("Suspicious TLD (.ru, .tk, .xyz etc.)")
    if f["has_double_slash"]:      score+=10; issues.append("Double-slash redirect trick")
    score = min(score, 100)
    return {
        "risk_level": "High" if score>=60 else "Medium" if score>=30 else "Low",
        "score": score,
        "prediction": "Phishing URL" if score>=60 else "Suspicious URL" if score>=30 else "Likely Safe",
        "issues": issues if issues else ["No major issues detected"]
    }
