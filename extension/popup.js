// popup.js — PhishNet v3
// Full frontend-parity results: ML score, confidence, tactics, explanation, safety tips, risk bar

// ─────────────────────────────────────
// 🔑 PASTE YOUR API KEY HERE
// ─────────────────────────────────────
const ANTHROPIC_API_KEY = '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 api key';
const BACKEND_URL = 'http://localhost:8000';

let currentLang = 'en';

// ── i18n ─────────────────────────────
const STRINGS = {
  en: { analyzing:'Analyzing with ML + AI…', empty_msg:'Please paste a message.', empty_url:'Please paste a URL.' },
  hi: { analyzing:'ML + AI से विश्लेषण हो रहा है…', empty_msg:'कृपया संदेश डालें।', empty_url:'कृपया URL डालें।' },
  kn: { analyzing:'ML + AI ಜೊತೆ ವಿಶ್ಲೇಷಿಸಲಾಗುತ್ತಿದೆ…', empty_msg:'ದಯವಿಟ್ಟು ಸಂದೇಶ ನೀಡಿ.', empty_url:'ದಯವಿಟ್ಟು URL ನೀಡಿ.' }
};
function s(k) { return (STRINGS[currentLang]||STRINGS.en)[k] || STRINGS.en[k] || k; }

function setLang(lang) {
  currentLang = lang;
  document.querySelectorAll('.lang-btn').forEach(b => b.classList.remove('active'));
  document.querySelector(`.lang-btn[onclick="setLang('${lang}')"]`)?.classList.add('active');
  chrome.storage.local.set({ lang });
}

function showTab(tab) {
  document.getElementById('textSection').classList.toggle('active', tab==='text');
  document.getElementById('urlSection').classList.toggle('active', tab==='url');
  document.getElementById('msgTab').classList.toggle('active', tab==='text');
  document.getElementById('urlTabBtn').classList.toggle('active', tab==='url');
  document.getElementById('resultBox').innerHTML = '';
}

function autofillCurrentURL() {
  chrome.tabs.query({ active:true, currentWindow:true }, tabs => {
    if (tabs?.[0]?.url) document.getElementById('urlInput').value = tabs[0].url;
  });
}

function scanCurrentPage() {
  chrome.tabs.query({ active:true, currentWindow:true }, tabs => {
    if (tabs?.[0]?.id) {
      chrome.tabs.sendMessage(tabs[0].id, { type:'SCAN_PAGE' });
      showInfo('🔍 Scanning page for threats…');
      setTimeout(() => document.getElementById('resultBox').innerHTML = '', 3000);
    }
  });
}

// ── Backend health ────────────────────
async function checkHealth() {
  try {
    const r = await fetch(BACKEND_URL + '/health', { signal: AbortSignal.timeout(2000) });
    const d = await r.json();
    const mlDot  = document.getElementById('mlDot');
    const aiDot  = document.getElementById('aiDot');
    const mlText = document.getElementById('mlText');
    const aiText = document.getElementById('aiText');
    if (mlDot) { mlDot.className = d.ml ? 'chip-dot live' : 'chip-dot warn'; }
    if (aiDot) { aiDot.className = d.ai ? 'chip-dot live' : 'chip-dot warn'; }
    if (mlText) { mlText.textContent = d.ml ? 'ML ✓' : 'ML ✗'; mlText.style.color = d.ml ? 'var(--safe)' : 'var(--warn)'; }
    if (aiText) { aiText.textContent = d.ai ? 'AI ✓' : 'AI ✗'; aiText.style.color = d.ai ? 'var(--safe)' : 'var(--warn)'; }
  } catch {
    const mlText = document.getElementById('mlText');
    const aiText = document.getElementById('aiText');
    if (mlText) { mlText.textContent = 'ML offline'; mlText.style.color = 'var(--muted)'; }
    if (aiText) { aiText.textContent = 'AI offline'; aiText.style.color = 'var(--muted)'; }
  }
}

// ── Rule-based tactics ────────────────
const TACTIC_MAP = [
  { re:/urgent|immediately|now|asap|act fast|deadline|expire|24 hour|limited time/i, label:'Urgency' },
  { re:/bank|account|paypal|netflix|amazon|microsoft|apple|google|irs|social security/i, label:'Authority Impersonation' },
  { re:/suspend|block|arrest|penalty|fine|lose access|terminated|legal action/i, label:'Fear / Threat' },
  { re:/free|won|winner|prize|gift|reward|claim|congratulation|selected/i, label:'Reward Bait' },
  { re:/verify|confirm|validate|update.*info|click here|login|credential/i, label:'Credential Harvesting' },
  { re:/password|otp|pin|security code|card number|cvv|ssn/i, label:'Sensitive Data Request' },
];
function detectTactics(text) {
  return TACTIC_MAP.filter(({re})=>re.test(text)).map(({label})=>label);
}

// ── Claude direct fallback ────────────
async function callClaude(prompt) {
  if (!ANTHROPIC_API_KEY || ANTHROPIC_API_KEY==='YOUR_API_KEY_HERE') throw new Error('Add your API key to popup.js');
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method:'POST',
    headers:{
      'Content-Type':'application/json',
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version':'2023-06-01',
      'anthropic-dangerous-direct-browser-access':'true'
    },
    body: JSON.stringify({ model:'claude-sonnet-4-20250514', max_tokens:1000, messages:[{role:'user',content:prompt}] })
  });
  if (!r.ok) { const e=await r.json().catch(()=>{}); throw new Error(e?.error?.message||`API ${r.status}`); }
  const d = await r.json();
  return d.content?.map(b=>b.text||'').join('')||'';
}

// ── FULL RESULT RENDERER ──────────────
// Mirrors all frontend features: verdict, ML badge, explanation, tactic tags, risk bar, safety tips
function renderResult(data, tabLabel) {
  const box = document.getElementById('resultBox');
  const isHigh = data.risk_level==='High';
  const isMed  = data.risk_level==='Medium';
  const cssType   = isHigh?'danger':isMed?'warn':'safe';
  const emoji     = isHigh?'🔴':isMed?'🟡':'🟢';
  const riskLabel = isHigh?'HIGH RISK — THREAT DETECTED':isMed?'SUSPICIOUS — REVIEW CAREFULLY':'SAFE — NO THREATS FOUND';
  const barColor  = isHigh?'#ff4444':isMed?'#ffd600':'#00e5a0';

  // Tactics + Issues combined
  const items = [...(data.tactics||[]), ...(data.issues||[])].filter(i => i && !i.includes('No clear') && !i.includes('No major'));
  const tagsHtml = items.map(t=>`<span class="tactic-tag">${t}</span>`).join('');

  // ML badge
  const mlHtml = (data.ml_used && data.ml_score!==undefined)
    ? `<div class="ml-badge">🤖 ML Score: ${data.ml_score}% &nbsp;·&nbsp; Confidence: ${data.ml_confidence}%</div>`
    : '';

  // Source row
  const srcHtml = data.source
    ? `<div class="source-row">Source: ${data.source}</div>`
    : '';

  // Safety tips
  const tips = data.safety_tips || [
    'Do not click links from unknown or suspicious messages.',
    'Verify the sender\'s identity before responding.',
    'Never share passwords, OTPs, or banking details.',
  ];
  const tipsHtml = tips.slice(0,3).map(t=>`<div class="tip-row"><span class="tip-arrow">›</span>${t}</div>`).join('');

  const barId = 'rbf-' + Date.now();

  box.innerHTML = `
    <div class="result-box ${cssType}">
      <div class="result-header">
        <span class="rdot"></span>
        ${tabLabel.toUpperCase()} ANALYSIS
        <span class="result-score">${data.score}/100</span>
      </div>
      <div class="result-body">
        <div class="verdict">${emoji} ${riskLabel}</div>
        ${mlHtml}
        ${srcHtml}
        <div class="explanation">${data.explanation || ''}</div>
        ${items.length ? `<div class="tactics">${tagsHtml}</div>` : ''}

        <div class="risk-bar-section">
          <div class="risk-bar-label-row">
            <span class="risk-bar-lbl">Risk Score</span>
            <span class="risk-bar-lbl" style="color:${barColor}">${data.score} / 100</span>
          </div>
          <div class="risk-bar-track">
            <div class="risk-bar-fill" id="${barId}" style="width:0%;background:${barColor}"></div>
          </div>
        </div>

        <div class="tips-section-inner">
          <div class="tips-section-lbl">Safety Reminders</div>
          ${tipsHtml}
        </div>
      </div>
    </div>`;

  // Animate bar
  requestAnimationFrame(()=>requestAnimationFrame(()=>{
    const f = document.getElementById(barId);
    if (f) f.style.width = data.score + '%';
  }));
}

function showInfo(msg) {
  document.getElementById('resultBox').innerHTML = `<div class="result-box info"><div class="result-header"><span class="rdot"></span>${msg}</div></div>`;
}
function showError(msg) {
  document.getElementById('resultBox').innerHTML = `<div class="result-box warn"><div class="result-header"><span class="rdot"></span>ERROR</div><div class="result-body" style="font-size:12px;opacity:0.72;padding:12px">${msg}</div></div>`;
}
function setLoading(id, v) { document.getElementById(id)?.classList.toggle('loading',v); }

// ── ANALYZE TEXT ─────────────────────
async function analyzeText() {
  const input = document.getElementById('messageInput').value.trim();
  if (!input) { showInfo(s('empty_msg')); return; }
  setLoading('analyzeTextBtn', true);
  showInfo(s('analyzing'));

  try {
    // Try backend first: ML + Rules + Claude AI
    let data;
    try {
      const r = await fetch(BACKEND_URL + '/analyze-text', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ message:input, lang:currentLang, use_ai:true }),
        signal: AbortSignal.timeout(8000)
      });
      if (r.ok) {
        data = await r.json();
        data.source = `ML Model + Claude AI`;
        data.ml_used = true;
      }
    } catch(_) {}

    if (!data) {
      // Fallback: local rules + direct Claude
      const lang = currentLang==='hi'?'Hindi':currentLang==='kn'?'Kannada':'English';
      const tactics = detectTactics(input);
      const tacticBonus = Math.min(tactics.length*8, 25);
      const aiText = await callClaude(
        `You are a cybersecurity expert. Analyze this message for phishing or social engineering.
Reply ONLY in this exact format (in ${lang}):
VERDICT: [SAFE/SUSPICIOUS/DANGEROUS]
SCORE: [0-100]
EXPLANATION: [1-2 sentences]

Message: """${input}"""`
      );
      const score  = parseInt(aiText.match(/SCORE:\s*(\d+)/i)?.[1]||'40');
      const expl   = aiText.match(/EXPLANATION:\s*(.+)/is)?.[1]?.trim() || aiText.trim();
      const final  = Math.min(score+tacticBonus, 100);
      data = {
        risk_level: final>=60?'High':final>=30?'Medium':'Low',
        score: final, tactics, explanation: expl, ml_used: false,
        safety_tips:['Do not click suspicious links.','Verify sender before responding.','Never share OTPs or passwords.'],
        source: 'Claude AI (offline mode)'
      };
    }

    renderResult(data, 'Message');
  } catch(e) { showError(e.message); }
  setLoading('analyzeTextBtn', false);
}

// ── ANALYZE URL ──────────────────────
async function analyzeURL() {
  const input = document.getElementById('urlInput').value.trim();
  if (!input) { showInfo(s('empty_url')); return; }
  setLoading('analyzeUrlBtn', true);
  showInfo('Scanning URL with ML + AI…');

  try {
    let data;
    try {
      const r = await fetch(BACKEND_URL + '/analyze-url', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ url:input, lang:currentLang, use_ai:true }),
        signal: AbortSignal.timeout(8000)
      });
      if (r.ok) {
        data = await r.json();
        data.source = 'URL Features + Claude AI';
      }
    } catch(_) {}

    if (!data) {
      // Fallback: local JS URL scorer + Claude
      const urlResult = scoreURL(input);
      const lang = currentLang==='hi'?'Hindi':currentLang==='kn'?'Kannada':'English';
      let explanation = 'URL analyzed using structural feature detection.';
      try {
        const aiText = await callClaude(
          `You are a cybersecurity expert. Analyze this URL for phishing.
Reply ONLY in this format (in ${lang}):
VERDICT: [SAFE/SUSPICIOUS/DANGEROUS]
EXPLANATION: [1-2 sentences]

URL: ${input}
Detected issues: ${urlResult.issues.join(', ')}`
        );
        explanation = aiText.match(/EXPLANATION:\s*(.+)/is)?.[1]?.trim() || aiText;
      } catch(_) {}
      data = {
        ...urlResult, explanation,
        safety_tips:['Check domain spelling before clicking.','Look for HTTPS on any login page.','Avoid links with IP addresses.'],
        source: 'URL Rules + Claude AI (offline)'
      };
    }

    renderResult(data, 'URL');
  } catch(e) { showError(e.message); }
  setLoading('analyzeUrlBtn', false);
}

// ── INIT ─────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  chrome.storage.local.get(['lang','prefill'], res => {
    setLang(res.lang || 'en');
    if (res.prefill) {
      if (res.prefill.type==='text') { showTab('text'); document.getElementById('messageInput').value=res.prefill.value; }
      else { showTab('url'); document.getElementById('urlInput').value=res.prefill.value; }
      chrome.storage.local.remove(['prefill']);
    }
  });
  checkHealth();
});
