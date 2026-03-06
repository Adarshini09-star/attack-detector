// detection_engine.js — PhishNet Smart Detection Engine
// Fixes false positives on legitimate bank alerts, OTP messages, transaction notifications

// ══════════════════════════════════════════════
// TRUSTED SENDERS — never flag these as threats
// ══════════════════════════════════════════════
const TRUSTED_SENDERS = [
  // Indian Banks
  'hdfcbank', 'hdfc', 'icicibank', 'icici', 'sbibank', 'sbi', 'axisbank', 'axis',
  'kotakbank', 'kotak', 'yesbank', 'pnb', 'bankofbaroda', 'bob', 'unionbank',
  'canarabank', 'indusind', 'idfcfirst', 'rblbank', 'federalbank',
  // Payment systems
  'paytm', 'phonepe', 'googlepay', 'gpay', 'amazonpay', 'bhim', 'npci',
  // Official alert domains
  'alerts.hdfcbank.com', 'alerts@icicibank.com', 'alerts.sbi',
  'noreply@paytm.com', 'alerts@axisbank.com',
  // International banks
  'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'barclays', 'hsbc',
  // Cards
  'visa', 'mastercard', 'rupay', 'amex',
  // Utilities / Services
  'irctc', 'uidai', 'incometax', 'gst', 'epfo', 'aadhaar',
];

// ══════════════════════════════════════════════
// LEGITIMATE MESSAGE PATTERNS
// These strongly indicate a real transactional message
// ══════════════════════════════════════════════
const LEGITIMATE_PATTERNS = [
  // UPI / Transaction patterns (very specific, real formats)
  /Rs\.?\s*\d+(\.\d{1,2})?\s*(has been|is)\s*(debited|credited|transferred)/i,
  /debited from.*VPA\s+[\w.@]+/i,
  /credited to.*VPA\s+[\w.@]+/i,
  /UPI\s*(transaction|txn|ref|reference)\s*(number|no|id)?\.?\s*[:#]?\s*\d{6,}/i,
  /transaction\s*(reference|ref|id)\s*(number|no)?\.?\s*[:#]?\s*\d{6,}/i,

  // OTP patterns from banks (bank name + OTP context)
  /OTP\s*(for|is|:)\s*\d{4,8}/i,
  /your\s*(one.time|one time)\s*(password|passcode|otp)\s*(is|:)\s*\d{4,8}/i,
  /\d{4,8}\s*is\s*(your|the)\s*(otp|one.time\s*password)/i,

  // Balance / Account notifications
  /available\s*balance\s*(is|:)\s*Rs\.?\s*[\d,]+/i,
  /a\/c\s*(no\.?|number)?\s*[xX*]+\d{4}/i,
  /account\s*(ending|no\.?|number)?\s*[xX*]+\d{4}/i,

  // Standard bank alert formats
  /dear\s*(customer|user),?\s*Rs\.?\s*\d+/i,
  /ROLL\s*ME\b/i,  // HDFC specific format
  /NEFT|RTGS|IMPS|UPI|NACH/i,
];

// ══════════════════════════════════════════════
// HIGH-CONFIDENCE PHISHING SIGNALS
// These are very specific to attacks, not legitimate messages
// ══════════════════════════════════════════════
const STRONG_PHISHING_SIGNALS = [
  // Requests to click + do something sensitive
  /click\s*(here|this\s*link|below|now)\s*(to\s*)?(verify|confirm|update|login|reset|claim|access)/i,
  /follow\s*this\s*link\s*(to\s*)?(verify|reset|claim)/i,

  // Threatening consequences
  /your\s*account\s*(will\s*be|has\s*been|is\s*being)\s*(suspended|blocked|terminated|closed|locked|deleted)/i,
  /will\s*be\s*(arrested|penalised|fined|charged|sued)\s*(if|unless)/i,
  /avoid\s*(arrest|penalty|legal\s*action|suspension)\s*(by\s*)?(clicking|paying|calling)/i,

  // Prize / lottery scams
  /you\s*(have\s*)?(won|been\s*selected|are\s*the\s*winner)\s*(a\s*)?\$([\d,]+|prize|gift|reward)/i,
  /claim\s*your\s*(prize|reward|gift|winnings)\s*(now|immediately|today)/i,
  /\$\d+\s*(gift\s*card|reward|prize)\s*(waiting|available|ready)/i,

  // Credential harvesting with urgency
  /update\s*your\s*(payment|billing|credit\s*card|debit\s*card)\s*(info|details|information)\s*(immediately|now|urgently)/i,
  /your\s*(password|login|credentials)\s*(has\s*been\s*compromised|were\s*exposed|is\s*at\s*risk)/i,
  /verify\s*your\s*(identity|account)\s*(immediately|within\s*\d+\s*hours?|or\s*(lose|your\s*account))/i,

  // Nigerian prince / advance fee
  /transfer\s*(funds?|money)\s*(of\s*)?\$[\d,]+\s*(million|thousand)/i,
  /i\s*(am|represent)\s*(a\s*)?(prince|minister|official)\s*from/i,
  /need\s*your\s*(help|assistance)\s*(to\s*)?(transfer|move)\s*(funds?|\$)/i,

  // Fake IT support
  /your\s*(computer|device|pc|laptop)\s*(has\s*a?\s*virus|is\s*infected|has\s*been\s*hacked)/i,
  /call\s*(microsoft|apple|google)\s*(support|helpline)\s*(immediately|now|urgently)/i,
];

// ══════════════════════════════════════════════
// CONTEXTUAL TACTIC MAP
// Only trigger these when NOT in a legitimate context
// ══════════════════════════════════════════════
const CONTEXTUAL_TACTICS = [
  {
    re: /urgent|act fast|deadline|limited time|expires? (today|tonight|now)|24.hour/i,
    label: 'Urgency',
    // Don't flag if it's an OTP expiry (legitimate)
    whitelist: /otp.*expir|expir.*otp|valid.*\d+\s*min/i
  },
  {
    re: /suspend|block|arrest|penalty|fine|lose access|terminated|legal action/i,
    label: 'Fear / Threat',
    // Don't flag if it's a legitimate account statement context
    whitelist: /transaction|debited|credited|balance|statement/i
  },
  {
    re: /won|winner|prize|gift|reward|claim|congratulation|selected|lucky/i,
    label: 'Reward Bait',
    whitelist: /cashback|loyalty|points\s*earned|reward\s*points/i
  },
  {
    re: /verify|confirm|validate|click here|credential/i,
    label: 'Credential Harvesting',
    // Don't flag "verify" in OTP messages from banks
    whitelist: /otp|transaction|debit|credit|payment|VPA/i
  },
  {
    re: /password|otp|pin|cvv|ssn/i,
    label: 'Sensitive Data Request',
    // Only flag if ASKING for these, not if it's providing/mentioning them transactionally
    whitelist: /your otp is|otp for|otp:|\d{4,8}\s*is your|transaction|debited|credited/i
  },
];

// ══════════════════════════════════════════════
// MAIN SCORING FUNCTION
// Returns: { score, risk_level, tactics, is_legitimate, explanation }
// ══════════════════════════════════════════════
function smartScore(text, senderHint = '') {
  const t = text || '';
  const sender = (senderHint || '').toLowerCase();

  // 1. Check trusted sender → cap score at 20 (Low) unless strong phishing signals
  const isTrustedSender = TRUSTED_SENDERS.some(ts =>
    sender.includes(ts) || t.toLowerCase().includes(`from ${ts}`) || t.toLowerCase().includes(`by ${ts}`)
  );

  // 2. Check legitimate patterns — strong indicator this is a real transactional message
  const legitimateMatches = LEGITIMATE_PATTERNS.filter(p => p.test(t));
  const isLegitimate = legitimateMatches.length > 0;

  // 3. Check strong phishing signals — these override everything
  const strongPhishingMatches = STRONG_PHISHING_SIGNALS.filter(p => p.test(t));
  const hasStrongPhishing = strongPhishingMatches.length > 0;

  // 4. Contextual tactics (smart — respects whitelists)
  const tactics = [];
  for (const { re, label, whitelist } of CONTEXTUAL_TACTICS) {
    if (re.test(t)) {
      // If whitelisted context, don't count this tactic
      if (whitelist && whitelist.test(t)) continue;
      tactics.push(label);
    }
  }

  // ── SCORING LOGIC ──────────────────────────
  let score = 0;

  if (hasStrongPhishing) {
    // Strong phishing signals → high score regardless
    score = 55 + (strongPhishingMatches.length * 12);
  } else if (isLegitimate && isTrustedSender) {
    // Trusted sender + legitimate pattern → very low score
    score = 5 + (tactics.length * 3);
  } else if (isLegitimate) {
    // Legitimate pattern but unknown sender → low-medium
    score = 10 + (tactics.length * 5);
  } else if (isTrustedSender) {
    // Trusted sender but unusual content → low
    score = 15 + (tactics.length * 6);
  } else {
    // Unknown sender, no legitimate patterns
    score = 20 + (tactics.length * 10);
  }

  score = Math.min(score, 100);

  const risk_level = score >= 60 ? 'High' : score >= 35 ? 'Medium' : 'Low';

  // Build explanation
  let explanation = '';
  if (isLegitimate && !hasStrongPhishing) {
    explanation = `This appears to be a legitimate transactional notification (${legitimateMatches.length > 0 ? 'matches known bank alert format' : 'standard notification pattern'}).`;
    if (isTrustedSender) explanation += ' Sender is a recognized institution.';
  } else if (hasStrongPhishing) {
    explanation = `Contains ${strongPhishingMatches.length} high-confidence phishing indicator${strongPhishingMatches.length > 1 ? 's' : ''}.`;
  } else if (tactics.length > 0) {
    explanation = `Contains ${tactics.length} suspicious tactic${tactics.length > 1 ? 's' : ''}: ${tactics.join(', ')}.`;
  } else {
    explanation = 'No significant threats detected.';
  }

  return {
    score,
    risk_level,
    tactics,
    is_legitimate: isLegitimate && !hasStrongPhishing,
    explanation
  };
}
