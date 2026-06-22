// Shared helpers for the inspection console.
const GATES = [
  {n:"01", id:"charguard",  t:"charguard",       d:"Deterministic character &amp; encoding pass"},
  {n:"02", id:"promptguard", t:"Prompt Guard 2",  d:"Prompt-injection shield"},
  {n:"03", id:"inspector",  t:"Inspector",        d:"LLM leakage judgment"},
];

async function api(method, path, opts={}){
  const r = await fetch(path, {method, ...opts});
  if(!r.ok){ let m; try{m=(await r.json()).detail}catch(e){m=r.statusText} throw new Error(m||("HTTP "+r.status)); }
  return r.status===204 ? null : r.json();
}
const esc = s => (s==null?"":String(s)).replace(/[&<>"']/g, c=>(
  {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function fmtBytes(n){
  if(n<1024) return n+" B";
  if(n<1048576) return (n/1024).toFixed(1)+" KB";
  return (n/1048576).toFixed(2)+" MB";
}
function fmtTime(sec){
  if(!sec) return "—";
  const d=new Date(sec*1000);
  return d.toLocaleString(undefined,{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"});
}
const verdict = d => d ? `<span class="v ${esc(d)}">${esc(d)}</span>` : "";
function statusChip(s,d){
  if(s==="DONE"||s==="ERROR") return verdict(d||"REVIEW");
  if(s==="RUNNING") return `<span class="chip run">running</span>`;
  if(s==="QUEUED") return `<span class="chip">queued</span>`;
  if(s==="SKIPPED") return `<span class="chip">skipped</span>`;
  return `<span class="chip pend">pending</span>`;
}

// Render the three-gate rail. `hits` maps gate id -> label string (e.g. "1 finding"),
// `benign` is a set of gate ids that ran clean.
function renderRail(hits={}, benign=new Set()){
  return `<div class="rail">` + GATES.map(g=>{
    const hit = hits[g.id];
    const cls = hit ? "gate hit" : (benign.has(g.id) ? "gate benign" : "gate");
    const flag = hit ? `<span class="flag">${esc(hit)}</span>`
                     : (benign.has(g.id) ? `<span class="flag">clear</span>` : "");
    return `<div class="${cls}"><div class="n">${g.n}</div>${flag}
      <div class="t">${g.t}</div><div class="d">${g.d}</div></div>`;
  }).join("") + `</div>`;
}

async function fillStation(){
  const el = document.getElementById("station-stat");
  if(!el) return;
  try{
    const h = await api("GET","/api/health");
    const ib = h.inspector_backend || h.backend;
    const mock = ib==="mock";
    const model = (h.inspector_model||"").split("/").pop();
    el.innerHTML = `<span class="dot" style="background:${mock?'var(--review)':'var(--pass)'};
      box-shadow:0 0 0 3px ${mock?'var(--review-bg)':'var(--pass-bg)'}"></span>`+
      `inspector <span>${esc(ib)}</span> &nbsp;·&nbsp; <span>${esc(model)}</span>`;
  }catch(e){ el.textContent="backend offline"; }
}
document.addEventListener("DOMContentLoaded", fillStation);
