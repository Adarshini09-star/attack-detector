// url_features.js
// Ported from url_features.py — rule-based URL risk scorer (runs entirely in the extension, no backend needed)

const PHISHING_KEYWORDS = [
  "login","verify","update","secure","banking","account",
  "confirm","paypal","ebay","amazon","apple","microsoft",
  "support","password","signin","wallet","free","lucky",
  "winner","claim","urgent","suspended","alert","netflix",
  "refund","prize","reward","limited","expire","blocked"
];

const SUSPICIOUS_TLDS = [
  ".ru",".cn",".tk",".ml",".ga",".cf",".gq",".xyz",
  ".top",".pw",".cc"
];

function extractURLFeatures(url) {
  let parsed;
  try { parsed = new URL(url.startsWith("http") ? url : "http://" + url); }
  catch(e) { parsed = { hostname: "", pathname: "", search: "", protocol: "" }; }

  const hostname = parsed.hostname || "";
  const path     = parsed.pathname || "";

  return {
    url_length:            url.length,
    has_https:             parsed.protocol === "https:" ? 1 : 0,
    has_at_symbol:         url.includes("@") ? 1 : 0,
    has_ip:                /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname) ? 1 : 0,
    num_dots:              url.split(".").length - 1,
    num_hyphens:           (url.match(/-/g) || []).length,
    num_subdomains:        Math.max(hostname.split(".").length - 2, 0),
    has_phishing_keyword:  PHISHING_KEYWORDS.some(k => url.toLowerCase().includes(k)) ? 1 : 0,
    has_suspicious_tld:    SUSPICIOUS_TLDS.some(t => url.toLowerCase().endsWith(t) || url.toLowerCase().includes(t + "/")) ? 1 : 0,
    has_double_slash:      (url.split("//").length - 1) > 1 ? 1 : 0,
    path_length:           path.length,
    has_query_params:      parsed.search ? 1 : 0,
  };
}

function scoreURL(url) {
  const f      = extractURLFeatures(url);
  const issues = [];
  let score    = 0;

  if (f.url_length > 75)          { score += 15; issues.push("Unusually long URL"); }
  if (!f.has_https)                { score += 20; issues.push("No HTTPS — insecure connection"); }
  if (f.has_at_symbol)             { score += 25; issues.push("@ symbol (browser redirect trick)"); }
  if (f.has_ip)                    { score += 30; issues.push("IP address instead of domain name"); }
  if (f.num_dots > 4)              { score += 15; issues.push("Excessive subdomains"); }
  if (f.num_hyphens > 3)           { score += 10; issues.push("Excessive hyphens in domain"); }
  if (f.has_phishing_keyword)      { score += 25; issues.push("Phishing keywords detected in URL"); }
  if (f.has_suspicious_tld)        { score += 25; issues.push("Suspicious TLD (.ru, .tk, .xyz, etc.)"); }
  if (f.has_double_slash)          { score += 10; issues.push("Double-slash redirect trick in path"); }

  score = Math.min(score, 100);

  const risk_level = score >= 60 ? "High" : score >= 30 ? "Medium" : "Low";
  const prediction = score >= 60 ? "Phishing URL" : score >= 30 ? "Suspicious URL" : "Likely Safe";

  return {
    risk_level,
    score,
    prediction,
    issues: issues.length ? issues : ["No major issues detected"]
  };
}
