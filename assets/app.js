/* ══ DATA ══════════════════════════════════ */
const LIKELIHOOD = [
  { v:1, code:"01", label:"Rare",     desc:"Incredibly low probability. No active exploit vectors observed in current threat intelligence feeds." },
  { v:2, code:"02", label:"Unlikely", desc:"Requires highly specific misconfiguration. No recent telemetry indicates active reconnaissance." },
  { v:3, code:"03", label:"Likely",   desc:"Standard target conditions met. Comparable events logged across peer infrastructure in last 90 days." },
  { v:4, code:"04", label:"Frequent", desc:"Highly vulnerable surface. Multiple incidents recorded in current fiscal cycle." },
  { v:5, code:"05", label:"Certain",  desc:"Active exploit vectors confirmed. Event already observed multiple times in monitored telemetry." },
];
const IMPACT = [
  { v:1, label:"Insignificant",         short:"Insig" },
  { v:2, label:"Minor",                 short:"Minor" },
  { v:3, label:"Moderate",              short:"Mod" },
  { v:4, label:"Significant Material",  short:"Signif" },
  { v:5, label:"Catastrophic Failure",  short:"Crit" },
];

let likelihood = null, impact = null, phase = "idle";
let timers = [], scoreHistory = [], matrixMode = "score";

/* ══ RISK LEVELS (single source of truth) ══
   NIST SP 800-30 Rev.1, Appendix I, Table I-2: the level of risk is read from
   likelihood (rows) and impact (columns), each on the five qualitative levels
   Very Low … Very High. Likelihood 1-5 and impact 1-5 map to those levels in
   order. L × I is kept as a ranking aid only; it does not decide the level. */
const LEVELS = ["Very Low","Low","Moderate","High","Very High"];
const TIERS = {
  VL:{ key:"vlow",  label:"Very_Low",  cls:"c-vlow", pill:"p-vlow", tone:"t-vlow", protocol:"DEFCON_5_NOMINAL",
       resource:"Within accepted tolerance. No action required beyond the annual risk review.",
       response:"Record the assessment. Revisit at the next annual review." },
  L: { key:"low",   label:"Low",       cls:"c-low",  pill:"p-low",  tone:"t-low",  protocol:"DEFCON_4_MONITORED",
       resource:"Accept or mitigate at the risk owner's discretion. Log for the quarterly risk audit.",
       response:"Log findings. Include in the next scheduled security review. No elevated response required." },
  M: { key:"mod",   label:"Moderate",  cls:"c-mod",  pill:"p-mod",  tone:"t-mod",  protocol:"DEFCON_3_MITIGATION",
       resource:"Standard mitigation playbook applies. Assign to the security team backlog with weekly monitoring.",
       response:"Document findings, schedule a remediation sprint, verify access controls on the affected surface." },
  H: { key:"high",  label:"High",      cls:"c-high", pill:"p-high", tone:"t-high", protocol:"DEFCON_2_ELEVATION",
       resource:"Material remediation budget required. Engage the security operations center and the incident response playbook.",
       response:"Apply hardening controls, verify backup integrity, confirm logging coverage, notify the risk committee." },
  VH:{ key:"vhigh", label:"Very_High", cls:"c-crit", pill:"p-crit", tone:"t-crit", protocol:"DEFCON_1_ESCALATION",
       resource:"Projected costs exceed contingency budgets. Executive notification and cyber insurance escalation required within 2 hours.",
       response:"Isolate affected network segments. Rotate credentials for privileged operators. Engage the CISO and legal." },
};
// RISK_MATRIX[likelihood][impact - 1], rows and columns ordered Very Low … Very High
const RISK_MATRIX = {
  5:["VL","L","M","H","VH"],
  4:["VL","L","M","H","VH"],
  3:["VL","L","M","M","H"],
  2:["VL","L","L","L","M"],
  1:["VL","VL","VL","L","L"],
};
function tierAt(l,i){ return TIERS[RISK_MATRIX[l][i-1]]; }
function p2(n){ return String(n).padStart(2,"0"); }
function nowTs(){ const d=new Date(); return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`; }

/* ══ CLOCK ═════════════════════════════════ */
function tickClock(){
  const t=nowTs();
  document.getElementById("hdr-clock").textContent=t;
  document.getElementById("ftMeta").textContent=`Local_Session // ${t}`;
}
setInterval(tickClock,1000); tickClock();

/* ══ PRELOADER ══════════════════════════════ */
const preStatuses = [
  "INITIALIZING RISK ASSESSMENT…",
  "LOADING NIST SP 800-30 FRAMEWORK…",
  "CALIBRATING THREAT MATRICES…",
  "LOADING SCORING BANDS…",
  "SYSTEM ONLINE",
];
let pIdx=0;
const preStatus = document.getElementById("preStatus");
const preInt = setInterval(()=>{
  pIdx++;
  if(pIdx<preStatuses.length){ preStatus.textContent=preStatuses[pIdx]; }
  else{
    clearInterval(preInt);
    setTimeout(()=>{ document.getElementById("preloader").classList.add("hidden"); },300);
  }
},360);

/* ══ BACKGROUND CANVAS ══════════════════════ */
(function(){
  const canvas = document.getElementById("bg-canvas");
  const ctx = canvas.getContext("2d");
  let W,H,pts=[];
  function resize(){ W=canvas.width=window.innerWidth; H=canvas.height=window.innerHeight; }
  resize(); window.addEventListener("resize",resize);
  for(let i=0;i<60;i++) pts.push({x:Math.random()*2000,y:Math.random()*1200,vx:(Math.random()-.5)*0.12,vy:(Math.random()-.5)*0.12,r:Math.random()*1.2+0.2,a:Math.random()});
  function draw(){
    ctx.clearRect(0,0,W,H);
    pts.forEach(p=>{
      p.x+=p.vx; p.y+=p.vy;
      if(p.x<0)p.x=W; if(p.x>W)p.x=0;
      if(p.y<0)p.y=H; if(p.y>H)p.y=0;
      ctx.beginPath(); ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
      ctx.fillStyle=`rgba(0,212,255,${p.a*0.5})`;
      ctx.fill();
    });
    // connection lines
    for(let i=0;i<pts.length;i++){
      for(let j=i+1;j<pts.length;j++){
        const dx=pts[i].x-pts[j].x, dy=pts[i].y-pts[j].y;
        const d=Math.sqrt(dx*dx+dy*dy);
        if(d<160){
          ctx.beginPath(); ctx.moveTo(pts[i].x,pts[i].y); ctx.lineTo(pts[j].x,pts[j].y);
          ctx.strokeStyle=`rgba(0,212,255,${(1-d/160)*0.06})`; ctx.lineWidth=0.5; ctx.stroke();
        }
      }
    }
    requestAnimationFrame(draw);
  }
  draw();
})();

/* ══ RADAR ANIMATION ═══════════════════════ */
(function(){
  const sweep = document.getElementById("radar-sweep");
  let angle=0;
  function tick(){
    angle=(angle+0.8)%360;
    const rad=angle*Math.PI/180;
    const ex=80+70*Math.cos(rad), ey=80+70*Math.sin(rad);
    const la=angle>180?1:0;
    sweep.querySelector("path").setAttribute("d",`M80,80 L${80+70},80 A70,70 0 ${la},1 ${ex},${ey} Z`);
    sweep.querySelector("line").setAttribute("x2",ex);
    sweep.querySelector("line").setAttribute("y2",ey);
    requestAnimationFrame(tick);
  }
  tick();
})();

/* ══ MATRIX RAIN ═══════════════════════════ */
function buildRain(el){
  const chars="01アウエオカキクコサシスセソ!@#$%^&*";
  for(let i=0;i<4;i++){
    const col=document.createElement("div");
    col.className="rain-col";
    col.style.left=`${i*15}px`;
    col.style.animationDuration=`${3+Math.random()*4}s`;
    col.style.animationDelay=`-${Math.random()*5}s`;
    let txt="";
    for(let j=0;j<18;j++) txt+=chars[Math.floor(Math.random()*chars.length)];
    col.textContent=txt;
    el.appendChild(col);
  }
}
buildRain(document.getElementById("rainLeft"));

/* ══ BUILD LIKELIHOOD ═══════════════════════ */
const likeGrid = document.getElementById("likeGrid");
LIKELIHOOD.forEach(o=>{
  const b=document.createElement("button");
  b.className="like-btn"; b.dataset.v=o.v;
  b.innerHTML=`
    <div class="lripple"></div>
    <span class="lcode mono">${o.code}</span>
    <span class="llbl">${o.label}</span>
    <div class="lbar"></div>`;
  b.onclick=()=>{ likelihood=o.v; renderInputs(); };
  likeGrid.appendChild(b);
});

/* ══ BUILD IMPACT ═══════════════════════════ */
const impactList = document.getElementById("impactList");
IMPACT.forEach(o=>{
  const b=document.createElement("button");
  b.className="impact-btn"; b.dataset.v=o.v;
  const dots=[...Array(5)].map((_,i)=>`<div class="sev-dot"></div>`).join("");
  b.innerHTML=`
    <div class="ileft">
      <span class="inum mono">0${o.v}</span>
      <span class="ilbl">${o.label}</span>
    </div>
    <div class="impact-right">
      <div class="impact-sev">${dots}</div>
      <div class="impact-radio"><div class="impact-radio-dot"></div></div>
    </div>`;
  b.onclick=()=>{ impact=o.v; renderInputs(); };
  impactList.appendChild(b);
});

/* ══ BUILD MATRIX ═══════════════════════════ */
const ROWS=[5,4,3,2,1], COLS=[1,2,3,4,5];
const matrixGrid=document.getElementById("matrixGrid");
const xLabels=document.getElementById("xLabels");
const yLabels=document.getElementById("yLabels");
const yLbls=IMPACT.slice().reverse();

yLbls.forEach((o,i)=>{
  const d=document.createElement("div");
  d.className="matrix-y-lbl"; d.dataset.r=ROWS[i]; d.textContent=o.short;
  yLabels.appendChild(d);
});

ROWS.forEach(r=>{
  COLS.forEach(c=>{
    const s=r*c;
    const cell=document.createElement("div");
    cell.className=`cell ${tierAt(c,r).tone}`;
    cell.dataset.r=r; cell.dataset.c=c; cell.dataset.s=s;
    cell.innerHTML=`
      <span class="cell-coord">${c},${r}</span>
      <span class="cell-val mono">${p2(s)}</span>
      <span class="cell-glyph">◆</span>
      <div class="reticle-tl"></div><div class="reticle-tr"></div>
      <div class="reticle-bl"></div><div class="reticle-br"></div>`;
    matrixGrid.appendChild(cell);
  });
});

COLS.forEach(c=>{
  const d=document.createElement("div");
  d.className="matrix-x-lbl"; d.dataset.c=c; d.textContent=`L${c}`;
  xLabels.appendChild(d);
});

/* ══ MATRIX MODE ════════════════════════════ */
function setMode(m){
  matrixMode=m;
  document.querySelectorAll(".mode-btn").forEach(b=>{
    b.classList.toggle("active",b.dataset.mode===m);
  });
  document.querySelectorAll(".cell").forEach(cell=>{
    const val=cell.querySelector(".cell-val");
    const coord=cell.querySelector(".cell-coord");
    const glyph=cell.querySelector(".cell-glyph");
    if(m==="score"){ val.style.display=""; coord.style.display=""; glyph.style.display=""; }
    if(m==="heat"){  val.style.display="none"; coord.style.display="none"; glyph.style.display="none"; }
    if(m==="clean"){ val.style.display="none"; coord.style.display="none"; glyph.style.display="none"; }
  });
}

document.querySelectorAll(".mode-btn").forEach(b=>{
  b.addEventListener("click",()=>setMode(b.dataset.mode));
});

/* ══ CROSSHAIR ══════════════════════════════ */
function updateCrosshair(){
  const crossH=document.getElementById("crossH");
  const crossV=document.getElementById("crossV");
  if(!likelihood||!impact){ crossH.style.opacity="0"; crossV.style.opacity="0"; return; }
  const rowIdx=ROWS.indexOf(impact);
  const colIdx=COLS.indexOf(likelihood);
  const cellH=`${100/5}%`;
  crossH.style.top=`calc(${rowIdx}*${cellH} + ${rowIdx}*4px)`;
  crossH.style.height=cellH;
  crossH.style.opacity="1";
  crossV.style.left=`calc(${colIdx}*${cellH} + ${colIdx}*4px)`;
  crossV.style.width=cellH;
  crossV.style.opacity="1";
}

/* ══ RENDER INPUTS ══════════════════════════ */
function renderInputs(){
  // likelihood
  document.querySelectorAll(".like-btn").forEach(b=>{
    b.classList.toggle("active",+b.dataset.v===likelihood);
  });
  const desc=document.getElementById("likeDesc");
  if(likelihood){ desc.textContent=LIKELIHOOD[likelihood-1].desc; desc.classList.remove("hidden"); }
  else desc.classList.add("hidden");

  // impact
  document.querySelectorAll(".impact-btn").forEach(b=>{
    b.classList.toggle("active",+b.dataset.v===impact);
  });

  // matrix cells
  document.querySelectorAll(".cell").forEach(cell=>{
    const r=+cell.dataset.r, c=+cell.dataset.c;
    const sel=(c===likelihood&&r===impact);
    const rowHl=(r===impact), colHl=(c===likelihood);
    cell.classList.toggle("selected", sel);
    cell.classList.toggle("highlighted", !sel&&(rowHl||colHl));
    cell.classList.toggle("dimmed", !!(likelihood&&impact)&&!sel&&!rowHl&&!colHl);
  });

  // axis labels
  document.querySelectorAll(".matrix-x-lbl").forEach(d=>d.classList.toggle("active",+d.dataset.c===likelihood));
  document.querySelectorAll(".matrix-y-lbl").forEach(d=>d.classList.toggle("active",+d.dataset.r===impact));

  updateCrosshair();

  // formula live
  const s=(likelihood&&impact)?likelihood*impact:0;
  document.getElementById("formulaEq").innerHTML=
    `<span class="hl">L</span>(${p2(likelihood||0)}) × <span class="hl">I</span>(${p2(impact||0)}) = <span class="eq-result">${p2(s)}</span>`;

  document.getElementById("execBtn").disabled=!(likelihood&&impact)||phase==="arming";
}

/* ══ SPARKLINE ══════════════════════════════ */
function updateSparkline(){
  if(scoreHistory.length<2) return;
  const svg=document.getElementById("sparklineSvg");
  const W=260, H=40, pad=4;
  const max=Math.max(...scoreHistory,1);
  const pts=scoreHistory.map((v,i)=>{
    const x=pad+(i/(scoreHistory.length-1))*(W-pad*2);
    const y=H-pad-(v/max)*(H-pad*2);
    return `${x},${y}`;
  });
  const line=pts.join(" ");
  const area=[`${pad},${H}`, ...pts, `${W-pad},${H}`].join(" ");
  document.getElementById("sparklineLine").setAttribute("points",line);
  document.getElementById("sparklineArea").setAttribute("points",area);
}

/* ══ LOG ════════════════════════════════════ */
function appendLog(tag,tone,text){
  const body=document.getElementById("logBody");
  const div=document.createElement("div");
  div.className=`log-line ${tone}`;
  const ts=document.createElement("span"); ts.className="log-ts"; ts.textContent=`[${nowTs()}]`;
  const tg=document.createElement("span"); tg.className="log-tag"; tg.textContent=`[${tag}]`;
  div.append(ts," ",tg," ",text);
  body.appendChild(div);
  body.scrollTop=body.scrollHeight;
}

/* ══ EXECUTE ════════════════════════════════ */
function clearTimers(){ timers.forEach(clearTimeout); timers=[]; }

/* SHA-256 over the assessment record. Web Crypto needs a secure context (https or localhost). */
async function digestRecord(record){
  if(!(window.crypto&&crypto.subtle)) return null;
  const bytes=new TextEncoder().encode(JSON.stringify(record));
  const buf=await crypto.subtle.digest("SHA-256",bytes);
  return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,"0")).join("");
}

let runId=0;

document.getElementById("execBtn").onclick=async()=>{
  if(!likelihood||!impact) return;
  clearTimers();
  const run=++runId;
  phase="arming";
  document.getElementById("execLbl").textContent="Computing…";
  document.getElementById("execBtn").disabled=true;
  document.getElementById("resetBtn").classList.remove("hidden");
  document.getElementById("ftPhaseDot").className="ft-dot amber";
  document.getElementById("ftPhaseLbl").textContent="Computing";

  const s=likelihood*impact;
  const t=tierAt(likelihood,impact);
  const L=LIKELIHOOD[likelihood-1], I=IMPACT[impact-1];
  const field=id=>document.getElementById(id).value.trim();
  const record={
    version:2,
    assessedAt:new Date().toISOString(),
    title:field("recTitle"),
    assessor:field("recAssessor"),
    rationale:field("recRationale"),
    method:"NIST SP 800-30 Rev.1 Appendix I Table I-2",
    likelihood:{ value:L.v, label:L.label, level:LEVELS[L.v-1] },
    impact:{ value:I.v, label:I.label, level:LEVELS[I.v-1] },
    score:s,
    riskLevel:LEVELS[Object.values(TIERS).indexOf(t)],
  };
  const digest=await digestRecord(record);
  if(run!==runId) return; // reset while hashing
  scoreHistory.push(s);
  updateSparkline();

  // Every line below is derived from the user's inputs; nothing is simulated
  const stream=[
    { tag:"SYS",   tone:"tone-sys",   delay:0,    text:"INITIALIZING_RISK_COORDINATES…" },
    { tag:"DATA",  tone:"tone-data",  delay:260,  text:`MAPPING VECTOR: LIKELIHOOD_${p2(L.v)} (${L.label.toUpperCase()} → ${record.likelihood.level.toUpperCase()}) × IMPACT_${p2(I.v)} (${I.label.toUpperCase()} → ${record.impact.level.toUpperCase()})` },
    { tag:"DATA",  tone:"tone-data",  delay:520,  text:`RANKING SCORE = L × I = ${p2(L.v)} × ${p2(I.v)} = ${p2(s)} / 25` },
    { tag:"EVAL",  tone:"tone-eval",  delay:800,  text:`SP 800-30 TABLE I-2: ${record.likelihood.level.toUpperCase()} × ${record.impact.level.toUpperCase()} → ${record.riskLevel.toUpperCase()} RISK` },
    { tag:"EVAL",  tone:"tone-eval",  delay:1060, text:`RESPONSE PROTOCOL: ${t.protocol}` },
    { tag: t.key==="vhigh"?"ALERT":"OK", tone: t.key==="vhigh"?"tone-alert":"tone-ok", delay:1340,
      text: t.key==="vhigh" ? "⚠ VERY HIGH RISK — ESCALATION RECOMMENDED" : "CALCULATION COMPLETE." },
    { tag:"SYS",   tone:"tone-sys",   delay:1620,
      text: digest ? `RECORD DIGEST: SHA-256 ${digest.slice(0,16)}… · SAVED IN THIS BROWSER, NOT TRANSMITTED`
                   : "RECORD DIGEST UNAVAILABLE: WEB CRYPTO NEEDS HTTPS OR LOCALHOST" },
  ];

  document.getElementById("logBody").innerHTML="";
  document.getElementById("ind1").className="log-ind on";
  document.getElementById("ind2").className="log-ind";
  document.getElementById("ind3").className="log-ind";

  stream.forEach((line,i)=>{
    const timer=setTimeout(()=>{
      appendLog(line.tag,line.tone,line.text);
      if(i===2) document.getElementById("ind2").className="log-ind on";
      if(i===stream.length-1){ document.getElementById("ind3").className="log-ind done"; finalize(s,t,record,digest); }
    }, line.delay);
    timers.push(timer);
  });
};

/* ══ FINALIZE ═══════════════════════════════ */
function finalize(s,t,record,digest){
  phase="result";
  document.getElementById("execLbl").textContent="Execute Calculation";
  document.getElementById("ftPhaseDot").className="ft-dot gray";
  document.getElementById("ftPhaseLbl").textContent="Idle";

  // score animate
  const sv=document.getElementById("scoreVal");
  sv.className=`score-val mono ${t.cls}`;
  animateCount(sv,0,s,700);

  // tier pill
  const pill=document.getElementById("tierPill");
  pill.className=`tier-pill ${t.pill}`;
  pill.textContent=t.label;

  // threat meta
  const meta=document.getElementById("threatMeta");
  meta.classList.remove("hidden");

  // risk bar
  const fill=document.getElementById("riskBarFill");
  fill.className=`risk-bar-fill ${t.cls}`;
  setTimeout(()=>{ fill.style.width=`${(s/25)*100}%`; },50);

  document.getElementById("resourceText").textContent=t.resource;

  const protoBadge=document.getElementById("protoBadge");
  protoBadge.className=`proto-badge ${t.cls}`;
  protoBadge.textContent=t.protocol;

  document.getElementById("protoText").textContent=t.response;

  const recName=document.getElementById("auditFileName");
  recName.textContent=`ASSESSMENT_${record.assessedAt.replace(/[-:]/g,"").slice(0,15)}Z`;
  recName.title=JSON.stringify(record);
  const recDigest=document.getElementById("auditFileSize");
  recDigest.textContent=digest ? `SHA-256 · ${digest.slice(0,24)}…` : "SHA-256 · unavailable (needs HTTPS)";
  recDigest.title=digest||"";

  addToRegister(record,digest);
}

/* ══ COUNT ANIMATION ════════════════════════ */
function animateCount(el,from,to,dur){
  const t0=performance.now();
  function step(t){
    const p=Math.min(1,(t-t0)/dur);
    const e=1-Math.pow(1-p,4);
    el.textContent=p2(Math.round(from+(to-from)*e));
    if(p<1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/* ══ RESET ══════════════════════════════════ */
const RECORD_FIELDS=["recTitle","recAssessor","recRationale"];

document.getElementById("resetBtn").onclick=()=>{
  // Completed assessments are already in the register; only unsaved notes can be lost
  const unsaved=phase!=="result" && RECORD_FIELDS.some(id=>document.getElementById(id).value.trim());
  if(unsaved && !window.confirm("Discard this assessment and its notes? It has not been saved to the register yet.")) return;
  clearTimers();
  runId++;
  likelihood=null; impact=null; phase="idle";
  RECORD_FIELDS.forEach(id=>{ document.getElementById(id).value=""; });
  document.getElementById("logBody").innerHTML=`<div class="log-empty">Awaiting parameters — execute calculation to stream evidence</div>`;
  document.getElementById("scoreVal").textContent="00";
  document.getElementById("scoreVal").className="score-val mono";
  document.getElementById("tierPill").className="tier-pill hidden";
  document.getElementById("threatMeta").classList.add("hidden");
  document.getElementById("riskBarFill").style.width="0";
  document.getElementById("resetBtn").classList.add("hidden");
  document.getElementById("ind1").className="log-ind";
  document.getElementById("ind2").className="log-ind";
  document.getElementById("ind3").className="log-ind";
  document.getElementById("formulaEq").innerHTML=
    `<span class="hl">L</span>(00) × <span class="hl">I</span>(00) = <span class="eq-result">00</span>`;
  updateCrosshair();
  renderInputs();
};

/* ══ REGISTER ═══════════════════════════════
   Kept in localStorage as a per-browser convenience. Export is the system of
   record: storage can be cleared, blocked or unavailable (private windows). */
const REGISTER_KEY="nist-risk-register-v1";
let register=[], storageOk=true;

function loadRegister(){
  try{
    const raw=window.localStorage.getItem(REGISTER_KEY);
    const parsed=raw?JSON.parse(raw):[];
    register=Array.isArray(parsed)?parsed.filter(e=>e&&e.record&&typeof e.record.assessedAt==="string"):[];
  }catch(e){ storageOk=false; register=[]; }
}
function saveRegister(){
  try{ window.localStorage.setItem(REGISTER_KEY,JSON.stringify(register)); storageOk=true; }
  catch(e){ storageOk=false; }
}
function addToRegister(record,digest){
  register.push({ record, sha256:digest||null });
  saveRegister();
  renderRegister();
}

function tierKeyFor(level){ return Object.values(TIERS)[LEVELS.indexOf(level)]||TIERS.M; }

function renderRegister(){
  const body=document.getElementById("registerBody");
  body.replaceChildren();
  // Newest first; every value is set with textContent, never parsed as HTML
  register.slice().reverse().forEach(entry=>{
    const r=entry.record, tr=document.createElement("tr");
    const td=(text,cls)=>{ const c=document.createElement("td"); if(cls) c.className=cls; c.textContent=text; tr.appendChild(c); return c; };
    td(r.assessedAt.replace("T"," ").slice(0,19),"mono");
    const title=td(r.title||"(untitled)","reg-title");
    if(r.rationale) title.title=r.rationale;
    td(`${r.likelihood.value} · ${r.likelihood.level}`,"mono");
    td(`${r.impact.value} · ${r.impact.level}`,"mono");
    td(p2(r.score),"mono");
    const lvl=td("",""); const badge=document.createElement("span");
    badge.className=`reg-level ${tierKeyFor(r.riskLevel).pill}`; badge.textContent=r.riskLevel; lvl.appendChild(badge);
    td(r.assessor||"—");
    const sha=td(entry.sha256?`${entry.sha256.slice(0,12)}…`:"unavailable","mono");
    if(entry.sha256) sha.title=entry.sha256;
    body.appendChild(tr);
  });
  const empty=register.length===0;
  document.getElementById("registerEmpty").classList.toggle("hidden",!empty);
  ["exportJsonBtn","exportCsvBtn","clearRegisterBtn"].forEach(id=>{ document.getElementById(id).disabled=empty; });
  document.getElementById("registerNote").textContent=storageOk
    ? "Every completed assessment is kept in this browser only. Export to keep a copy."
    : "Browser storage is unavailable, so assessments last until this tab closes. Export to keep a copy.";
}

function download(name,type,text){
  const url=URL.createObjectURL(new Blob([text],{type}));
  const a=document.createElement("a");
  a.href=url; a.download=name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function stamp(){ return new Date().toISOString().replace(/[-:]/g,"").slice(0,15); }

// Spreadsheet formula injection: a cell starting with = + - @ tab or CR is neutralised
function csvCell(v){
  let text=v==null?"":String(v);
  if(/^[=+\-@\t\r]/.test(text)) text="'"+text;
  return `"${text.replace(/"/g,'""')}"`;
}

document.getElementById("exportJsonBtn").addEventListener("click",()=>{
  const doc={ exportedAt:new Date().toISOString(), method:"NIST SP 800-30 Rev.1 Appendix I Table I-2",
              entries:register.map(e=>({ ...e.record, sha256:e.sha256 })) };
  download(`nist-risk-register-${stamp()}.json`,"application/json",JSON.stringify(doc,null,2));
});
document.getElementById("exportCsvBtn").addEventListener("click",()=>{
  const cols=["assessedAt","title","assessor","likelihood","likelihoodLevel","impact","impactLevel","score","riskLevel","rationale","sha256"];
  const rows=register.map(({record:r,sha256})=>[r.assessedAt,r.title,r.assessor,r.likelihood.value,r.likelihood.level,
    r.impact.value,r.impact.level,r.score,r.riskLevel,r.rationale,sha256]);
  const csv=[cols,...rows].map(row=>row.map(csvCell).join(",")).join("\r\n");
  download(`nist-risk-register-${stamp()}.csv`,"text/csv",csv);
});
document.getElementById("clearRegisterBtn").addEventListener("click",()=>{
  if(!window.confirm(`Delete all ${register.length} assessments from this browser? Export first if you need them.`)) return;
  register=[];
  saveRegister();
  renderRegister();
});

/* ══ INIT ═══════════════════════════════════ */
loadRegister();
renderRegister();
renderInputs();
