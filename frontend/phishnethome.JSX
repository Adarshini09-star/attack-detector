import { useState, useEffect, useRef, useCallback } from "react";

const API = "http://127.0.0.1:8000";

// ─── Helpers ───────────────────────────────────────────────────────────────────
const riskColor = r => ({ High: "#ef4444", Medium: "#f59e0b", Low: "#22c55e" }[r] || "#94a3b8");
const riskBg   = r => ({ High: "rgba(239,68,68,0.08)", Medium: "rgba(245,158,11,0.08)", Low: "rgba(34,197,94,0.08)" }[r] || "transparent");

// ─── Scan lines ────────────────────────────────────────────────────────────────
const ScanLines = () => (
  <div style={{
    position:"fixed",inset:0,pointerEvents:"none",zIndex:50,
    background:"repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,200,0.015) 2px,rgba(0,255,200,0.015) 4px)"
  }}/>
);

// ─── Blinking cursor ───────────────────────────────────────────────────────────
const Cursor = () => {
  const [v,setV]=useState(true);
  useEffect(()=>{const t=setInterval(()=>setV(x=>!x),530);return()=>clearInterval(t);},[]);
  return <span style={{opacity:v?1:0,color:"#00ffc8"}}>█</span>;
};

// ─── Animated counter ──────────────────────────────────────────────────────────
const Counter=({target,suffix=""})=>{
  const [val,setVal]=useState(0);
  useEffect(()=>{
    let s=0;const step=Math.ceil(target/60);
    const t=setInterval(()=>{s=Math.min(s+step,target);setVal(s);if(s>=target)clearInterval(t);},20);
    return()=>clearInterval(t);
  },[target]);
  return <span>{val.toLocaleString()}{suffix}</span>;
};

// ─── Live threat ticker ────────────────────────────────────────────────────────
const THREATS=[
  "ALERT: New SMS phishing campaign targeting banking credentials",
  "BLOCKED: Malicious URL impersonating HDFC Bank login portal",
  "DETECTED: OTP harvesting via social engineering — India Region",
  "WARNING: Lottery scam wave detected across 14 mobile networks",
  "INTERCEPTED: Credential phishing disguised as KYC verification",
];
const ThreatTicker=()=>{
  const [i,setI]=useState(0);const [fade,setFade]=useState(true);
  useEffect(()=>{
    const t=setInterval(()=>{setFade(false);setTimeout(()=>{setI(x=>(x+1)%THREATS.length);setFade(true);},400);},3500);
    return()=>clearInterval(t);
  },[]);
  return(
    <div style={{background:"rgba(239,68,68,0.08)",border:"1px solid rgba(239,68,68,0.3)",
      borderLeft:"3px solid #ef4444",padding:"10px 16px",fontFamily:"'Courier New',monospace",
      fontSize:"12px",color:"#fca5a5",transition:"opacity 0.4s",opacity:fade?1:0,
      display:"flex",gap:"10px",alignItems:"center"}}>
      <span style={{color:"#ef4444",fontWeight:700,flexShrink:0}}>▶ LIVE</span>
      {THREATS[i]}
    </div>
  );
};

// ─── Nav ───────────────────────────────────────────────────────────────────────
const Nav=({active,setActive})=>(
  <nav style={{display:"flex",justifyContent:"space-between",alignItems:"center",
    padding:"18px 48px",borderBottom:"1px solid rgba(0,255,200,0.15)",
    background:"rgba(2,6,23,0.95)",backdropFilter:"blur(12px)",
    position:"sticky",top:0,zIndex:40}}>
    <div style={{display:"flex",alignItems:"center",gap:"12px"}}>
      <div style={{width:36,height:36,border:"2px solid #00ffc8",borderRadius:"6px",
        display:"flex",alignItems:"center",justifyContent:"center",background:"rgba(0,255,200,0.08)"}}>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
          <path d="M12 2L4 6v6c0 5.5 3.5 10.7 8 12 4.5-1.3 8-6.5 8-12V6l-8-4z" stroke="#00ffc8" strokeWidth="1.5" fill="rgba(0,255,200,0.1)"/>
          <path d="M9 12l2 2 4-4" stroke="#00ffc8" strokeWidth="1.5" strokeLinecap="round"/>
        </svg>
      </div>
      <div>
        <div style={{fontFamily:"'Courier New',monospace",fontWeight:700,fontSize:"16px",color:"#00ffc8",letterSpacing:"3px"}}>PHISHNET</div>
        <div style={{fontFamily:"'Courier New',monospace",fontSize:"9px",color:"rgba(0,255,200,0.5)",letterSpacing:"2px"}}>THREAT DETECTION SYSTEM</div>
      </div>
    </div>
    <div style={{display:"flex",gap:"4px"}}>
      {["HOME","ANALYZE","ABOUT"].map(item=>(
        <button key={item} onClick={()=>setActive(item)} style={{
          padding:"8px 18px",
          background:active===item?"rgba(0,255,200,0.12)":"transparent",
          border:active===item?"1px solid rgba(0,255,200,0.4)":"1px solid transparent",
          color:active===item?"#00ffc8":"rgba(148,163,184,0.8)",
          fontFamily:"'Courier New',monospace",fontSize:"11px",letterSpacing:"2px",
          cursor:"pointer",borderRadius:"4px",transition:"all 0.2s"}}>{item}</button>
      ))}
    </div>
    <div style={{display:"flex",alignItems:"center",gap:"8px",fontFamily:"'Courier New',monospace",fontSize:"11px",color:"#22c55e"}}>
      <span style={{width:8,height:8,borderRadius:"50%",background:"#22c55e",display:"inline-block",
        boxShadow:"0 0 6px #22c55e",animation:"pulse 2s infinite"}}/>
      SYSTEM ONLINE
    </div>
  </nav>
);

// ─── Result Card ───────────────────────────────────────────────────────────────
const ResultCard=({result})=>{
  if(!result)return null;
  const rc=riskColor(result.risk_level);
  return(
    <div style={{marginTop:"20px",border:`1px solid ${rc}40`,borderLeft:`3px solid ${rc}`,
      borderRadius:"6px",padding:"20px",background:riskBg(result.risk_level),
      fontFamily:"'Courier New',monospace"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"16px"}}>
        <div style={{fontSize:"18px",fontWeight:700,color:rc,letterSpacing:"2px"}}>
          {result.risk_level?.toUpperCase()} RISK
        </div>
        <div style={{fontSize:"28px",fontWeight:700,color:rc}}>{result.score}<span style={{fontSize:"14px",color:"#64748b"}}>/100</span></div>
      </div>
      {result.threat_type&&(
        <div style={{fontSize:"11px",color:"#94a3b8",marginBottom:"10px",letterSpacing:"1px"}}>
          THREAT TYPE: <span style={{color:"#e2e8f0"}}>{result.threat_type}</span>
        </div>
      )}
      {result.keywords?.length>0&&(
        <div style={{marginBottom:"12px"}}>
          <div style={{fontSize:"10px",color:"#64748b",letterSpacing:"2px",marginBottom:"6px"}}>FLAGGED KEYWORDS</div>
          <div style={{display:"flex",gap:"6px",flexWrap:"wrap"}}>
            {result.keywords.map(k=>(
              <span key={k} style={{padding:"3px 8px",background:"rgba(239,68,68,0.15)",
                border:"1px solid rgba(239,68,68,0.3)",borderRadius:"3px",fontSize:"11px",color:"#fca5a5"}}>
                {k}
              </span>
            ))}
          </div>
        </div>
      )}
      {result.issues?.length>0&&(
        <div style={{marginBottom:"12px"}}>
          <div style={{fontSize:"10px",color:"#64748b",letterSpacing:"2px",marginBottom:"6px"}}>ISSUES DETECTED</div>
          {result.issues.map(issue=>(
            <div key={issue} style={{fontSize:"12px",color:"#fca5a5",marginBottom:"4px"}}>⚠ {issue}</div>
          ))}
        </div>
      )}
      {result.analysis_summary&&(
        <div style={{fontSize:"12px",color:"#94a3b8",borderTop:"1px solid rgba(255,255,255,0.06)",paddingTop:"12px",marginTop:"4px"}}>
          {result.analysis_summary}
        </div>
      )}
      {result.extracted_text&&(
        <div style={{marginTop:"12px",borderTop:"1px solid rgba(255,255,255,0.06)",paddingTop:"12px"}}>
          <div style={{fontSize:"10px",color:"#64748b",letterSpacing:"2px",marginBottom:"6px"}}>EXTRACTED TEXT</div>
          <div style={{fontSize:"11px",color:"#94a3b8",lineHeight:1.6,maxHeight:"120px",overflowY:"auto",
            background:"rgba(0,0,0,0.3)",padding:"10px",borderRadius:"4px",whiteSpace:"pre-wrap"}}>
            {result.extracted_text}
          </div>
        </div>
      )}
    </div>
  );
};

// ─── Text Analyzer ─────────────────────────────────────────────────────────────
const TextAnalyzer=()=>{
  const [msg,setMsg]=useState("");
  const [loading,setLoading]=useState(false);
  const [result,setResult]=useState(null);
  const [error,setError]=useState(null);

  const analyze=async()=>{
    if(!msg.trim())return;
    setLoading(true);setError(null);setResult(null);
    try{
      const res=await fetch(`${API}/analyze-text`,{method:"POST",
        headers:{"Content-Type":"application/json"},body:JSON.stringify({message:msg})});
      if(!res.ok)throw new Error(`Server returned ${res.status}`);
      setResult(await res.json());
    }catch(e){setError(e.message);}
    finally{setLoading(false);}
  };

  return(
    <div>
      <div style={{fontFamily:"'Courier New',monospace",fontSize:"10px",color:"rgba(0,255,200,0.5)",letterSpacing:"3px",marginBottom:"12px"}}>
        PASTE SUSPICIOUS MESSAGE BELOW
      </div>
      <textarea value={msg} onChange={e=>setMsg(e.target.value)}
        placeholder="e.g. Your account has been suspended. Click here to verify your OTP now..."
        style={{width:"100%",height:"120px",background:"rgba(15,23,42,0.8)",
          border:"1px solid rgba(0,255,200,0.2)",borderRadius:"6px",padding:"12px",
          color:"#e2e8f0",fontFamily:"'Courier New',monospace",fontSize:"13px",
          resize:"vertical",outline:"none",boxSizing:"border-box"}}/>
      <button onClick={analyze} disabled={loading||!msg.trim()} style={{
        marginTop:"12px",padding:"12px 28px",
        background:loading?"rgba(0,255,200,0.1)":"linear-gradient(135deg,#00ffc8,#00b4d8)",
        border:"none",borderRadius:"6px",color:loading?"#00ffc8":"#020617",
        fontFamily:"'Courier New',monospace",fontWeight:700,fontSize:"12px",
        letterSpacing:"2px",cursor:loading?"not-allowed":"pointer",width:"100%"}}>
        {loading?"⟳ ANALYZING...":"▶ ANALYZE TEXT"}
      </button>
      {error&&<div style={{marginTop:"12px",padding:"10px 14px",background:"rgba(239,68,68,0.1)",
        border:"1px solid rgba(239,68,68,0.3)",borderRadius:"4px",fontFamily:"'Courier New',monospace",
        fontSize:"12px",color:"#fca5a5"}}>⚠ {error}</div>}
      <ResultCard result={result}/>
    </div>
  );
};

// ─── URL Analyzer ──────────────────────────────────────────────────────────────
const URLAnalyzer=()=>{
  const [url,setUrl]=useState("");
  const [loading,setLoading]=useState(false);
  const [result,setResult]=useState(null);
  const [error,setError]=useState(null);

  const analyze=async()=>{
    if(!url.trim())return;
    setLoading(true);setError(null);setResult(null);
    try{
      const res=await fetch(`${API}/analyze-url`,{method:"POST",
        headers:{"Content-Type":"application/json"},body:JSON.stringify({url})});
      if(!res.ok)throw new Error(`Server returned ${res.status}`);
      setResult(await res.json());
    }catch(e){setError(e.message);}
    finally{setLoading(false);}
  };

  return(
    <div>
      <div style={{fontFamily:"'Courier New',monospace",fontSize:"10px",color:"rgba(0,255,200,0.5)",letterSpacing:"3px",marginBottom:"12px"}}>
        ENTER URL TO SCAN
      </div>
      <input value={url} onChange={e=>setUrl(e.target.value)}
        onKeyDown={e=>e.key==="Enter"&&analyze()}
        placeholder="https://suspicious-link.com/verify-account?token=abc123"
        style={{width:"100%",background:"rgba(15,23,42,0.8)",
          border:"1px solid rgba(0,255,200,0.2)",borderRadius:"6px",padding:"12px",
          color:"#e2e8f0",fontFamily:"'Courier New',monospace",fontSize:"13px",
          outline:"none",boxSizing:"border-box"}}/>
      <button onClick={analyze} disabled={loading||!url.trim()} style={{
        marginTop:"12px",padding:"12px 28px",
        background:loading?"rgba(0,255,200,0.1)":"linear-gradient(135deg,#00ffc8,#00b4d8)",
        border:"none",borderRadius:"6px",color:loading?"#00ffc8":"#020617",
        fontFamily:"'Courier New',monospace",fontWeight:700,fontSize:"12px",
        letterSpacing:"2px",cursor:loading?"not-allowed":"pointer",width:"100%"}}>
        {loading?"⟳ SCANNING...":"▶ SCAN URL"}
      </button>
      {error&&<div style={{marginTop:"12px",padding:"10px 14px",background:"rgba(239,68,68,0.1)",
        border:"1px solid rgba(239,68,68,0.3)",borderRadius:"4px",fontFamily:"'Courier New',monospace",
        fontSize:"12px",color:"#fca5a5"}}>⚠ {error}</div>}
      <ResultCard result={result}/>
    </div>
  );
};

// ─── Screenshot Analyzer ───────────────────────────────────────────────────────
const ScreenshotAnalyzer=()=>{
  const [file,setFile]=useState(null);
  const [preview,setPreview]=useState(null);
  const [loading,setLoading]=useState(false);
  const [result,setResult]=useState(null);
  const [error,setError]=useState(null);
  const [drag,setDrag]=useState(false);
  const inputRef=useRef();

  const handleFile=useCallback(f=>{
    if(!f)return;
    const allowed=["image/png","image/jpeg","image/webp","image/jpg"];
    if(!allowed.includes(f.type)){setError("Only PNG, JPG, WEBP supported.");return;}
    if(f.size>10*1024*1024){setError("File too large. Max 10MB.");return;}
    setFile(f);setError(null);setResult(null);
    const reader=new FileReader();
    reader.onload=e=>setPreview(e.target.result);
    reader.readAsDataURL(f);
  },[]);

  const onDrop=e=>{e.preventDefault();setDrag(false);handleFile(e.dataTransfer.files[0]);};

  const analyze=async()=>{
    if(!file)return;
    setLoading(true);setError(null);setResult(null);
    try{
      const fd=new FormData();fd.append("file",file);
      const res=await fetch(`${API}/analyze-screenshot`,{method:"POST",body:fd});
      if(!res.ok){
        let msg=`Server returned ${res.status}`;
        try{const d=await res.json();msg=d.detail||msg;}catch{}
        throw new Error(msg);
      }
      const data=await res.json();
      setResult({...data.analysis, extracted_text: data.extracted_text});
    }catch(e){setError(e.message);}
    finally{setLoading(false);}
  };

  return(
    <div>
      <div style={{fontFamily:"'Courier New',monospace",fontSize:"10px",color:"rgba(0,255,200,0.5)",letterSpacing:"3px",marginBottom:"12px"}}>
        UPLOAD SCREENSHOT
      </div>
      {/* Drop zone */}
      <div onDragOver={e=>{e.preventDefault();setDrag(true);}}
        onDragLeave={()=>setDrag(false)} onDrop={onDrop}
        onClick={()=>!file&&inputRef.current.click()}
        style={{border:`1px dashed ${drag?"#00ffc8":"rgba(0,255,200,0.3)"}`,
          borderRadius:"8px",padding:"32px",textAlign:"center",cursor:file?"default":"pointer",
          background:drag?"rgba(0,255,200,0.05)":"rgba(15,23,42,0.4)",transition:"all 0.2s",
          marginBottom:"12px"}}>
        {preview?(
          <div>
            <img src={preview} alt="preview" style={{maxWidth:"100%",maxHeight:"200px",
              borderRadius:"4px",border:"1px solid rgba(0,255,200,0.2)"}}/>
            <div style={{fontFamily:"'Courier New',monospace",fontSize:"11px",color:"#64748b",marginTop:"8px"}}>
              {file.name} · {(file.size/1024).toFixed(1)} KB
            </div>
            <button onClick={e=>{e.stopPropagation();setFile(null);setPreview(null);setResult(null);setError(null);}}
              style={{marginTop:"8px",padding:"4px 12px",background:"transparent",
                border:"1px solid rgba(239,68,68,0.4)",borderRadius:"4px",color:"#ef4444",
                fontFamily:"'Courier New',monospace",fontSize:"10px",cursor:"pointer",letterSpacing:"1px"}}>
              ✕ REMOVE
            </button>
          </div>
        ):(
          <div>
            <div style={{fontSize:"32px",marginBottom:"12px"}}>📸</div>
            <div style={{fontFamily:"'Courier New',monospace",fontSize:"13px",color:"#94a3b8",marginBottom:"6px"}}>
              Drop screenshot here or click to browse
            </div>
            <div style={{fontFamily:"'Courier New',monospace",fontSize:"10px",color:"#475569",letterSpacing:"1px"}}>
              PNG, JPG, WEBP · Max 10MB
            </div>
          </div>
        )}
      </div>
      <input ref={inputRef} type="file" accept="image/png,image/jpeg,image/webp"
        style={{display:"none"}} onChange={e=>handleFile(e.target.files[0])}/>

      <button onClick={analyze} disabled={loading||!file} style={{
        padding:"12px 28px",
        background:(!file||loading)?"rgba(0,255,200,0.08)":"linear-gradient(135deg,#00ffc8,#00b4d8)",
        border:(!file||loading)?"1px solid rgba(0,255,200,0.2)":"none",
        borderRadius:"6px",color:(!file||loading)?"rgba(0,255,200,0.4)":"#020617",
        fontFamily:"'Courier New',monospace",fontWeight:700,fontSize:"12px",
        letterSpacing:"2px",cursor:(!file||loading)?"not-allowed":"pointer",width:"100%"}}>
        {loading?"⟳ EXTRACTING & ANALYZING...":"▶ ANALYZE SCREENSHOT"}
      </button>

      {loading&&(
        <div style={{marginTop:"12px",fontFamily:"'Courier New',monospace",fontSize:"11px",
          color:"rgba(0,255,200,0.6)",textAlign:"center",letterSpacing:"2px"}}>
          Claude AI is extracting text from your screenshot...
        </div>
      )}

      {error&&<div style={{marginTop:"12px",padding:"10px 14px",background:"rgba(239,68,68,0.1)",
        border:"1px solid rgba(239,68,68,0.3)",borderRadius:"4px",fontFamily:"'Courier New',monospace",
        fontSize:"12px",color:"#fca5a5"}}>⚠ {error}</div>}
      <ResultCard result={result}/>
    </div>
  );
};

// ─── Analyze Page ──────────────────────────────────────────────────────────────
const AnalyzePage=({initTab="text"})=>{
  const [tab,setTab]=useState(initTab);
  const tabs=[{id:"text",label:"💬 TEXT"},{id:"url",label:"🔗 URL"},{id:"screenshot",label:"📸 SCREENSHOT"}];
  return(
    <section style={{padding:"40px 48px"}}>
      <div style={{fontFamily:"'Courier New',monospace",fontSize:"11px",color:"rgba(0,255,200,0.5)",letterSpacing:"3px",marginBottom:"8px"}}>
        — THREAT ANALYZER
      </div>
      <h2 style={{fontFamily:"'Courier New',monospace",fontSize:"24px",fontWeight:700,color:"#f8fafc",marginBottom:"32px"}}>
        SUBMIT FOR ANALYSIS
      </h2>
      <div style={{maxWidth:"680px"}}>
        <div style={{display:"flex",gap:"4px",marginBottom:"24px",
          background:"rgba(15,23,42,0.6)",border:"1px solid rgba(0,255,200,0.12)",
          borderRadius:"8px",padding:"4px"}}>
          {tabs.map(t=>(
            <button key={t.id} onClick={()=>setTab(t.id)} style={{
              flex:1,padding:"10px",
              background:tab===t.id?"rgba(0,255,200,0.12)":"transparent",
              border:tab===t.id?"1px solid rgba(0,255,200,0.3)":"1px solid transparent",
              color:tab===t.id?"#00ffc8":"#64748b",
              fontFamily:"'Courier New',monospace",fontSize:"11px",letterSpacing:"2px",
              cursor:"pointer",borderRadius:"5px",transition:"all 0.2s"}}>
              {t.label}
            </button>
          ))}
        </div>
        <div style={{background:"rgba(15,23,42,0.6)",border:"1px solid rgba(0,255,200,0.12)",
          borderRadius:"8px",padding:"24px",position:"relative",overflow:"hidden"}}>
          <div style={{position:"absolute",top:0,left:0,right:0,height:"2px",
            background:"linear-gradient(90deg,#00ffc8,transparent)"}}/>
          {tab==="text"&&<TextAnalyzer/>}
          {tab==="url"&&<URLAnalyzer/>}
          {tab==="screenshot"&&<ScreenshotAnalyzer/>}
        </div>
      </div>
    </section>
  );
};

// ─── Home Page ─────────────────────────────────────────────────────────────────
const HomePage=({goAnalyze})=>(
  <>
    <section style={{padding:"80px 48px 60px",position:"relative",overflow:"hidden"}}>
      <div style={{position:"absolute",inset:0,zIndex:0,
        backgroundImage:"linear-gradient(rgba(0,255,200,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,200,0.04) 1px,transparent 1px)",
        backgroundSize:"40px 40px"}}/>
      <div style={{position:"absolute",top:"-100px",left:"50%",transform:"translateX(-50%)",
        width:"600px",height:"400px",borderRadius:"50%",
        background:"radial-gradient(ellipse,rgba(0,255,200,0.06) 0%,transparent 70%)",zIndex:0}}/>
      <div style={{position:"relative",zIndex:1,maxWidth:"800px"}}>
        <div style={{fontFamily:"'Courier New',monospace",fontSize:"11px",color:"#00ffc8",
          letterSpacing:"3px",marginBottom:"24px",display:"flex",alignItems:"center",gap:"10px"}}>
          <span style={{color:"rgba(0,255,200,0.4)"}}>///</span>
          PHISHNET v2.4 — POWERED BY CLAUDE SONNET
          <span style={{color:"rgba(0,255,200,0.4)"}}>///</span>
        </div>
        <h1 style={{fontFamily:"'Courier New',monospace",fontSize:"clamp(32px,5vw,58px)",
          fontWeight:700,lineHeight:1.1,color:"#f8fafc",marginBottom:"8px",letterSpacing:"-1px"}}>
          DETECT PHISHING
        </h1>
        <h1 style={{fontFamily:"'Courier New',monospace",fontSize:"clamp(32px,5vw,58px)",
          fontWeight:700,lineHeight:1.1,background:"linear-gradient(90deg,#00ffc8,#00b4d8)",
          WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent",
          marginBottom:"32px",letterSpacing:"-1px"}}>
          BEFORE IT STRIKES <Cursor/>
        </h1>
        <p style={{fontFamily:"'Courier New',monospace",fontSize:"15px",color:"#94a3b8",
          lineHeight:1.7,maxWidth:"580px",marginBottom:"40px"}}>
          AI-powered text, URL, and screenshot analysis to identify social engineering
          attacks, credential harvesting, and malicious links in real-time.
        </p>
        <div style={{display:"flex",gap:"16px",flexWrap:"wrap"}}>
          <button onClick={()=>goAnalyze("text")} style={{padding:"14px 32px",
            background:"linear-gradient(135deg,#00ffc8,#00b4d8)",border:"none",
            borderRadius:"6px",color:"#020617",fontFamily:"'Courier New',monospace",
            fontWeight:700,fontSize:"13px",letterSpacing:"2px",cursor:"pointer"}}>
            ▶ START ANALYZING
          </button>
        </div>
      </div>
    </section>

    <section style={{padding:"0 48px 60px"}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(180px,1fr))",
        gap:"1px",background:"rgba(0,255,200,0.1)",border:"1px solid rgba(0,255,200,0.15)",
        borderRadius:"8px",overflow:"hidden"}}>
        {[{val:2847193,suffix:"",label:"THREATS DETECTED"},{val:99,suffix:".2%",label:"DETECTION ACCURACY"},
          {val:142,suffix:"ms",label:"AVG ANALYSIS TIME"},{val:18,suffix:"K+",label:"ACTIVE USERS"}]
          .map(({val,suffix,label})=>(
          <div key={label} style={{padding:"28px 24px",background:"rgba(2,6,23,0.8)",textAlign:"center"}}>
            <div style={{fontFamily:"'Courier New',monospace",fontSize:"28px",fontWeight:700,color:"#00ffc8",marginBottom:"6px"}}>
              <Counter target={val} suffix={suffix}/>
            </div>
            <div style={{fontFamily:"'Courier New',monospace",fontSize:"10px",color:"rgba(148,163,184,0.6)",letterSpacing:"2px"}}>
              {label}
            </div>
          </div>
        ))}
      </div>
    </section>

    <section style={{padding:"20px 48px 60px"}}>
      <div style={{fontFamily:"'Courier New',monospace",fontSize:"11px",color:"rgba(0,255,200,0.5)",letterSpacing:"3px",marginBottom:"32px"}}>
        — CORE CAPABILITIES
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(280px,1fr))",gap:"20px"}}>
        {[
          {icon:"💬",title:"TEXT ANALYSIS",desc:"Paste any suspicious message. ML model + Claude AI analyze tone, keywords, and social engineering patterns instantly.",tags:["NLP","ML MODEL","KEYWORD DETECTION"],tab:"text"},
          {icon:"🔗",title:"URL SCANNER",desc:"Submit any link. Detects IP masking, suspicious redirects, phishing keywords, and domain spoofing in milliseconds.",tags:["DOMAIN ANALYSIS","IP DETECTION","REDIRECT CHAIN"],tab:"url"},
          {icon:"📸",title:"SCREENSHOT OCR",desc:"Upload any screenshot. Claude AI extracts all visible text and runs full phishing analysis automatically.",tags:["CLAUDE OCR","IMAGE ANALYSIS","AUTO-EXTRACT"],tab:"screenshot"},
        ].map(({icon,title,desc,tags,tab})=>(
          <div key={title} onClick={()=>goAnalyze(tab)}
            style={{background:"rgba(15,23,42,0.8)",border:"1px solid rgba(0,255,200,0.12)",
              borderRadius:"8px",padding:"28px",position:"relative",overflow:"hidden",
              cursor:"pointer",transition:"border-color 0.2s,transform 0.2s"}}
            onMouseEnter={e=>{e.currentTarget.style.borderColor="rgba(0,255,200,0.4)";e.currentTarget.style.transform="translateY(-2px)";}}
            onMouseLeave={e=>{e.currentTarget.style.borderColor="rgba(0,255,200,0.12)";e.currentTarget.style.transform="translateY(0)";}}>
            <div style={{position:"absolute",top:0,left:0,right:0,height:"2px",background:"linear-gradient(90deg,#00ffc8,transparent)"}}/>
            <div style={{fontSize:"28px",marginBottom:"16px"}}>{icon}</div>
            <div style={{fontFamily:"'Courier New',monospace",fontSize:"13px",fontWeight:700,color:"#00ffc8",letterSpacing:"3px",marginBottom:"12px"}}>{title}</div>
            <p style={{fontFamily:"'Courier New',monospace",fontSize:"13px",color:"#94a3b8",lineHeight:1.7,marginBottom:"20px"}}>{desc}</p>
            <div style={{display:"flex",gap:"6px",flexWrap:"wrap"}}>
              {tags.map(tag=>(
                <span key={tag} style={{fontFamily:"'Courier New',monospace",fontSize:"9px",letterSpacing:"1.5px",
                  padding:"4px 8px",border:"1px solid rgba(0,255,200,0.2)",borderRadius:"3px",color:"rgba(0,255,200,0.6)"}}>
                  {tag}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  </>
);

// ─── Footer ────────────────────────────────────────────────────────────────────
const Footer=()=>(
  <footer style={{borderTop:"1px solid rgba(0,255,200,0.12)",padding:"32px 48px",
    display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:"16px"}}>
    <div style={{fontFamily:"'Courier New',monospace",fontSize:"11px",color:"rgba(0,255,200,0.4)",letterSpacing:"2px"}}>
      PHISHNET © 2026 — POWERED BY CLAUDE SONNET API
    </div>
    <div style={{display:"flex",gap:"24px"}}>
      {["PRIVACY","TERMS","API DOCS","CONTACT"].map(link=>(
        <span key={link} style={{fontFamily:"'Courier New',monospace",fontSize:"10px",color:"#475569",letterSpacing:"2px",cursor:"pointer"}}>
          {link}
        </span>
      ))}
    </div>
  </footer>
);

// ─── Root ──────────────────────────────────────────────────────────────────────
export default function PhishNetApp() {
  const [page, setPage] = useState("HOME");
  const [initTab, setInitTab] = useState("text");

  const goAnalyze = (tab="text") => { setInitTab(tab); setPage("ANALYZE"); };

  const handleNav = p => {
    if(p==="ANALYZE") goAnalyze();
    else setPage(p);
  };

  return (
    <div style={{background:"#020617",minHeight:"100vh",color:"#f8fafc"}}>
      <style>{`
        @keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.4;}}
        *{box-sizing:border-box;margin:0;padding:0;}
        ::-webkit-scrollbar{width:4px;}
        ::-webkit-scrollbar-track{background:#020617;}
        ::-webkit-scrollbar-thumb{background:rgba(0,255,200,0.3);border-radius:2px;}
        textarea:focus,input:focus{border-color:rgba(0,255,200,0.5)!important;box-shadow:0 0 0 2px rgba(0,255,200,0.08);}
      `}</style>
      <ScanLines/>
      <Nav active={page} setActive={handleNav}/>
      <div style={{padding:"16px 48px 0"}}><ThreatTicker/></div>
      {page==="HOME"    && <HomePage goAnalyze={goAnalyze}/>}
      {page==="ANALYZE" && <AnalyzePage initTab={initTab}/>}
      {page==="ABOUT"   && (
        <section style={{padding:"60px 48px"}}>
          <div style={{fontFamily:"'Courier New',monospace",maxWidth:"600px"}}>
            <div style={{fontSize:"11px",color:"rgba(0,255,200,0.5)",letterSpacing:"3px",marginBottom:"20px"}}>— ABOUT</div>
            <h2 style={{color:"#f8fafc",fontSize:"24px",marginBottom:"20px"}}>PhishNet</h2>
            <p style={{color:"#94a3b8",fontSize:"13px",lineHeight:1.8}}>
              PhishNet is a real-time phishing detection system built with FastAPI, a trained ML classifier,
              and Claude Sonnet (Anthropic) for OCR and NLP analysis. It detects social engineering in text
              messages, URLs, and screenshots.
            </p>
          </div>
        </section>
      )}
      <Footer/>
    </div>
  );
}