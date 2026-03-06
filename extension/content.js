// content.js — PhishNet v3.1
// Smart detection: won't false-flag real bank alerts, OTPs, UPI notifications
// Uses detection_engine.js for context-aware scoring

const BACKEND = 'http://localhost:8000';
const ANTHROPIC_API_KEY = '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 api key';

const scannedTexts = new Set();
const scannedURLs  = new Set();
let   scanTimeout  = null;

// ── Extract sender info from Gmail ───────────
function getGmailSender() {
  const fromEl = document.querySelector('.gD, [email], .go');
  return fromEl?.getAttribute('email') || fromEl?.innerText || '';
}

// ── Inject styles once ────────────────────────
function injectStyles() {
  if (document.getElementById('phishnet-styles')) return;
  const s = document.createElement('style');
  s.id = 'phishnet-styles';
  s.textContent = `
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    .pn-banner {
      font-family: 'Space Grotesk', sans-serif !important;
      position: relative; margin: 0 0 8px 0;
      border-radius: 12px; overflow: hidden;
      box-shadow: 0 4px 24px rgba(0,0,0,0.35);
      animation: pnSlideIn 0.4s cubic-bezier(0.4,0,0.2,1) both;
      z-index: 9999;
    }
    @keyframes pnSlideIn {
      from { opacity:0; transform:translateY(-10px); }
      to   { opacity:1; transform:translateY(0); }
    }

    /* HIGH RISK — red */
    .pn-danger { background:#120404; border:1px solid rgba(255,55,55,0.32); }
    .pn-danger .pn-header { background:rgba(255,50,50,0.1); border-bottom:1px solid rgba(255,55,55,0.18); }
    .pn-danger .pn-accent { color:#ff5555; }
    .pn-danger .pn-bar-fill { background:linear-gradient(90deg,#ff3333,#ff8800); }
    .pn-danger .pn-tag { background:rgba(255,55,55,0.1); border:1px solid rgba(255,55,55,0.22); color:#ff9090; }
    .pn-danger .pn-dot { background:#ff4444; box-shadow:0 0 7px #ff4444; }

    /* SUSPICIOUS — amber */
    .pn-warn { background:#0e0b00; border:1px solid rgba(255,195,0,0.28); }
    .pn-warn .pn-header { background:rgba(255,195,0,0.07); border-bottom:1px solid rgba(255,195,0,0.16); }
    .pn-warn .pn-accent { color:#ffc800; }
    .pn-warn .pn-bar-fill { background:linear-gradient(90deg,#ffc800,#ff8c00); }
    .pn-warn .pn-tag { background:rgba(255,195,0,0.09); border:1px solid rgba(255,195,0,0.22); color:#ffe066; }
    .pn-warn .pn-dot { background:#ffc800; box-shadow:0 0 7px #ffc800; }

    /* SAFE — teal */
    .pn-safe { background:#020d07; border:1px solid rgba(0,195,120,0.28); }
    .pn-safe .pn-header { background:rgba(0,195,120,0.07); border-bottom:1px solid rgba(0,195,120,0.16); }
    .pn-safe .pn-accent { color:#00e5a0; }
    .pn-safe .pn-bar-fill { background:linear-gradient(90deg,#00e5a0,#00b4d8); }
    .pn-safe .pn-tag { background:rgba(0,229,160,0.09); border:1px solid rgba(0,229,160,0.2); color:#7dffd0; }
    .pn-safe .pn-dot { background:#00e5a0; box-shadow:0 0 7px #00e5a0; }

    .pn-header { display:flex; align-items:center; gap:9px; padding:9px 13px; }
    .pn-dot { width:7px; height:7px; border-radius:50%; flex-shrink:0; }
    .pn-logo { font-family:'JetBrains Mono',monospace; font-size:10.5px; font-weight:500; color:rgba(255,255,255,0.28); letter-spacing:0.06em; }
    .pn-verdict { font-weight:700; font-size:12.5px; }
    .pn-score-pill { margin-left:auto; font-family:'JetBrains Mono',monospace; font-size:10px; background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.09); padding:2px 8px; border-radius:100px; color:rgba(255,255,255,0.5); }
    .pn-close { background:none; border:none; cursor:pointer; color:rgba(255,255,255,0.25); font-size:15px; padding:0 0 0 5px; transition:color 0.15s; line-height:1; }
    .pn-close:hover { color:rgba(255,255,255,0.65); }

    .pn-body { padding:11px 13px 13px; }
    .pn-explanation { font-size:12px; line-height:1.6; color:rgba(215,215,228,0.8); margin-bottom:9px; }
    .pn-tags { display:flex; flex-wrap:wrap; gap:4px; margin-bottom:9px; }
    .pn-tag { font-family:'JetBrains Mono',monospace; font-size:9.5px; padding:2px 8px; border-radius:3px; }
    .pn-ml-row { font-family:'JetBrains Mono',monospace; font-size:9.5px; color:rgba(160,130,220,0.7); margin-bottom:7px; display:flex; align-items:center; gap:5px; }

    .pn-bar-wrap { display:flex; align-items:center; gap:9px; margin-bottom:9px; }
    .pn-bar-lbl { font-family:'JetBrains Mono',monospace; font-size:9px; color:rgba(180,180,200,0.4); white-space:nowrap; }
    .pn-bar-track { flex:1; height:4px; background:rgba(255,255,255,0.05); border-radius:2px; overflow:hidden; }
    .pn-bar-fill { height:100%; border-radius:2px; transition:width 0.8s cubic-bezier(0.4,0,0.2,1); }
    .pn-bar-pct { font-family:'JetBrains Mono',monospace; font-size:9px; color:rgba(180,180,200,0.45); min-width:26px; text-align:right; }

    .pn-tips { border-top:1px solid rgba(255,255,255,0.05); padding-top:8px; margin-top:2px; }
    .pn-tip { font-size:11px; color:rgba(170,170,190,0.58); padding:2px 0; display:flex; gap:5px; }
    .pn-tip-arr { color:rgba(0,229,255,0.5); flex-shrink:0; }

    /* Inline link highlight */
    .pn-link-warn { outline:2px solid #ffc800 !important; border-radius:3px !important; padding:0 2px !important; }
    .pn-link-danger { outline:2px solid #ff4444 !important; border-radius:3px !important; padding:0 2px !important; }
  `;
  document.head.appendChild(s);
}

// ── Build banner ──────────────────────────────
function buildBanner(data) {
  const isHigh = data.risk_level === 'High';
  const isMed  = data.risk_level === 'Medium';
  const cls    = isHigh ? 'pn-danger' : isMed ? 'pn-warn' : 'pn-safe';
  const emoji  = isHigh ? '🔴' : isMed ? '🟡' : '🟢';
  const label  = isHigh ? 'HIGH RISK — Threat Detected'
               : isMed  ? 'Suspicious — Review Carefully'
               :          'Safe — Legitimate Message';

  const items = [...(data.tactics||[])].filter(i => i && !i.includes('No clear'));
  const tagsHtml = items.map(t => `<span class="pn-tag">${t}</span>`).join('');

  const mlHtml = (data.ml_score !== undefined)
    ? `<div class="pn-ml-row">🤖 ML: ${data.ml_score}% &nbsp;·&nbsp; Confidence: ${data.ml_confidence}%</div>` : '';

  const tips = (data.safety_tips || [
    'Do not click links in suspicious messages.',
    'Verify sender identity before responding.',
    'Never share OTPs, PINs, or passwords.',
  ]).slice(0, 2);
  const tipsHtml = tips.map(t => `<div class="pn-tip"><span class="pn-tip-arr">›</span>${t}</div>`).join('');

  const id = 'pn-' + Date.now() + Math.random().toString(36).slice(2,6);

  const div = document.createElement('div');
  div.className = `pn-banner ${cls}`;
  div.id = id;
  div.innerHTML = `
    <div class="pn-header">
      <span class="pn-dot"></span>
      <span class="pn-logo">🛡 PHISHNET</span>
      <span class="pn-verdict pn-accent">${emoji} ${label}</span>
      <span class="pn-score-pill">${data.score}/100</span>
      <button class="pn-close" onclick="document.getElementById('${id}').remove()">✕</button>
    </div>
    <div class="pn-body">
      ${mlHtml}
      <div class="pn-explanation">${data.explanation || ''}</div>
      ${items.length ? `<div class="pn-tags">${tagsHtml}</div>` : ''}
      <div class="pn-bar-wrap">
        <span class="pn-bar-lbl">RISK</span>
        <div class="pn-bar-track"><div class="pn-bar-fill" id="${id}-bar" style="width:0%"></div></div>
        <span class="pn-bar-pct">${data.score}%</span>
      </div>
      ${(isHigh || isMed) ? `<div class="pn-tips">${tipsHtml}</div>` : ''}
    </div>`;

  setTimeout(() => {
    const f = document.getElementById(`${id}-bar`);
    if (f) f.style.width = data.score + '%';
  }, 120);

  return div;
}

// ── Analyze text: backend → local engine ─────
async function analyzeTextSmart(text, senderHint = '') {
  // Step 1: Run local smart engine first (instant, no API)
  const local = smartScore(text, senderHint);

  // If local engine says it's clearly legitimate, trust it — no API call needed
  if (local.is_legitimate && local.score < 30) {
    return { ...local, source: 'local-engine', skip_api: true };
  }

  // Step 2: Try backend (ML + Claude AI)
  try {
    const r = await fetch(BACKEND + '/analyze-text', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text, lang: 'en', use_ai: true }),
      signal: AbortSignal.timeout(6000)
    });
    if (r.ok) {
      const d = await r.json();
      // Blend: if local engine is very confident it's legit, cap the backend score
      if (local.is_legitimate) {
        d.score = Math.min(d.score, 28);
        d.risk_level = 'Low';
        d.explanation = `[Verified legitimate] ${d.explanation}`;
      }
      d.ml_used = true;
      return d;
    }
  } catch (_) {}

  // Step 3: Fallback — direct Claude with context hint
  if (ANTHROPIC_API_KEY && ANTHROPIC_API_KEY !== 'YOUR_API_KEY_HERE') {
    try {
      const r = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
          'anthropic-dangerous-direct-browser-access': 'true'
        },
        body: JSON.stringify({
          model: 'claude-sonnet-4-20250514',
          max_tokens: 400,
          messages: [{ role: 'user', content:
`You are a cybersecurity expert. Analyze this message for phishing or social engineering.

IMPORTANT CONTEXT: Real bank transaction alerts (UPI debits/credits, OTPs from banks, balance notifications) are LEGITIMATE even if they mention "account", "bank", "OTP", or "verify". Only flag messages that are trying to TRICK the user into clicking a link, calling a number, or giving up credentials.

Reply ONLY in this format:
VERDICT: [SAFE/SUSPICIOUS/DANGEROUS]
SCORE: [0-100]
EXPLANATION: [1-2 sentences]

${senderHint ? `Sender: ${senderHint}\n` : ''}Message: """${text.slice(0, 600)}"""`
          }]
        })
      });
      if (r.ok) {
        const d = await r.json();
        const txt = d.content?.map(b => b.text||'').join('') || '';
        const score = parseInt(txt.match(/SCORE:\s*(\d+)/i)?.[1] || '30');
        const expl  = txt.match(/EXPLANATION:\s*(.+)/is)?.[1]?.trim() || txt;
        const final = local.is_legitimate ? Math.min(score, 28) : score;
        return {
          risk_level: final >= 60 ? 'High' : final >= 35 ? 'Medium' : 'Low',
          score: final, tactics: local.tactics, explanation: expl,
          safety_tips: ['Do not click suspicious links.', 'Verify sender before responding.', 'Never share OTPs.'],
          source: 'Claude AI'
        };
      }
    } catch (_) {}
  }

  // Final fallback: return local engine result
  return local;
}

// ── Analyze URL ───────────────────────────────
async function analyzeURLSmart(url) {
  // Skip clearly internal/safe URLs
  if (!url.startsWith('http')) return null;
  const safeDomains = ['google.com','gmail.com','whatsapp.com','youtube.com','wikipedia.org','github.com','microsoft.com','apple.com','amazon.in','amazon.com','flipkart.com'];
  try {
    const host = new URL(url).hostname.replace('www.','');
    if (safeDomains.some(d => host === d || host.endsWith('.' + d))) return null;
  } catch(_) { return null; }

  try {
    const r = await fetch(BACKEND + '/analyze-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, lang: 'en', use_ai: true }),
      signal: AbortSignal.timeout(5000)
    });
    if (r.ok) return await r.json();
  } catch(_) {}
  return null;
}

// ══════════════════════════════════════════════
// GMAIL SCANNER
// ══════════════════════════════════════════════
async function scanGmail() {
  injectStyles();
  const sender = getGmailSender();

  // Scan open email body
  const emailBodies = document.querySelectorAll('.a3s.aiL, .ii.gt .a3s');
  for (const el of emailBodies) {
    const text = el.innerText?.trim();
    if (!text || text.length < 30) continue;
    const key = text.slice(0, 120);
    if (scannedTexts.has(key)) continue;
    scannedTexts.add(key);

    const data = await analyzeTextSmart(text, sender);

    // Only show banner for Medium or High — never spam the user with Safe banners on legit emails
    if (data.risk_level === 'High' || data.risk_level === 'Medium') {
      const banner = buildBanner(data);
      el.parentNode.insertBefore(banner, el);
    }
  }

  // Scan links in emails — highlight suspicious ones
  const links = document.querySelectorAll('.a3s a[href], .ii.gt a[href]');
  for (const a of links) {
    const url = a.href;
    if (!url || scannedURLs.has(url)) continue;
    scannedURLs.add(url);
    const data = await analyzeURLSmart(url);
    if (!data) continue;
    if (data.risk_level === 'High') {
      a.classList.add('pn-link-danger');
      a.title = `🔴 PhishNet HIGH RISK: ${data.explanation}`;
    } else if (data.risk_level === 'Medium') {
      a.classList.add('pn-link-warn');
      a.title = `🟡 PhishNet SUSPICIOUS: ${data.explanation}`;
    }
  }
}

// ══════════════════════════════════════════════
// WHATSAPP SCANNER
// ══════════════════════════════════════════════
async function scanWhatsApp() {
  injectStyles();

  const messages = document.querySelectorAll(
    '.message-in .selectable-text, [data-testid="msg-container"] .copyable-text'
  );

  for (const el of messages) {
    const text = el.innerText?.trim();
    if (!text || text.length < 25) continue;
    const key = text.slice(0, 90);
    if (scannedTexts.has(key)) continue;

    // Quick pre-filter: skip if clearly a normal short conversational message
    const hasAnySignal = STRONG_PHISHING_SIGNALS.some(p => p.test(text)) ||
                         CONTEXTUAL_TACTICS.some(({ re, whitelist }) => re.test(text) && !(whitelist && whitelist.test(text)));
    if (!hasAnySignal) continue; // skip — looks safe, save API calls

    scannedTexts.add(key);
    const data = await analyzeTextSmart(text, '');

    if (data.risk_level === 'High' || data.risk_level === 'Medium') {
      const bubble = el.closest('[data-testid="msg-container"]') || el.closest('.message-in');
      if (bubble) bubble.parentNode.insertBefore(buildBanner(data), bubble);
    }
  }

  // WhatsApp links
  const waLinks = document.querySelectorAll('.message-in a[href]');
  for (const a of waLinks) {
    const url = a.href;
    if (!url || scannedURLs.has(url)) continue;
    scannedURLs.add(url);
    const data = await analyzeURLSmart(url);
    if (!data) continue;
    if (data.risk_level === 'High') {
      a.classList.add('pn-link-danger');
      a.title = `🔴 PhishNet: ${data.explanation}`;
    } else if (data.risk_level === 'Medium') {
      a.classList.add('pn-link-warn');
      a.title = `🟡 PhishNet: ${data.explanation}`;
    }
  }
}

// ── Trigger ───────────────────────────────────
function triggerScan() {
  clearTimeout(scanTimeout);
  scanTimeout = setTimeout(() => {
    const host = window.location.hostname;
    if (host.includes('mail.google.com'))   scanGmail();
    else if (host.includes('whatsapp.com')) scanWhatsApp();
  }, 1500);
}

const observer = new MutationObserver(() => triggerScan());
observer.observe(document.body, { childList: true, subtree: true });
triggerScan();

chrome.runtime.onMessage.addListener(msg => {
  if (msg.type === 'SCAN_PAGE') {
    scannedTexts.clear();
    scannedURLs.clear();
    triggerScan();
  }
});
