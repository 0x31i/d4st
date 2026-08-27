"""The dast-ng web console single-page app (served by server.py). Terminal/hacker aesthetic:
deep ink ground, amber accent, monospace, severity stripes. Vanilla JS against the JSON API."""

INDEX_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>dast-ng console</title>
<style>
:root{
  --bg:#070a0f;--bg2:#0b0f16;--panel:#0d131c;--panel2:#111925;--line:#1c2733;
  --ink:#d7e0ea;--ink2:#8595a6;--ink3:#5b6b7c;
  --amber:#ffb454;--amber2:#f0a020;--green:#7fd962;--cyan:#59c2ff;
  --crit:#ff5370;--high:#ff8f40;--med:#ffb454;--low:#59c2ff;--info:#6b7c8f;
  --mono:"JetBrains Mono","SF Mono",ui-monospace,"Cascadia Code",Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--mono);font-size:13.5px;
  line-height:1.55;-webkit-font-smoothing:antialiased;height:100vh;overflow:hidden;
  background-image:radial-gradient(900px 500px at 90% -10%,#12202e30,transparent 60%);}
a{color:var(--cyan);text-decoration:none}
::selection{background:var(--amber);color:#0a0a0a}
.app{display:grid;grid-template-columns:290px 1fr;height:100vh}
/* sidebar */
.side{border-right:1px solid var(--line);background:var(--bg2);display:flex;flex-direction:column;min-height:0}
.logo{padding:16px 18px;border-bottom:1px solid var(--line)}
.logo .b{font-weight:700;letter-spacing:.28em;color:var(--amber);text-transform:uppercase;font-size:12px}
.logo .s{color:var(--ink3);font-size:11px;margin-top:3px}
.scans{overflow:auto;flex:1;padding:8px}
.scanitem{padding:11px 13px;border:1px solid transparent;border-radius:9px;cursor:pointer;margin-bottom:6px}
.scanitem:hover{background:var(--panel)}
.scanitem.sel{background:var(--panel2);border-color:var(--line)}
.scanitem .t{color:var(--ink);font-size:13px;word-break:break-all;display:flex;align-items:center;gap:8px}
.scanitem .meta{color:var(--ink3);font-size:11px;margin-top:5px;display:flex;gap:10px}
.gbadge{font-weight:800;font-size:12px;width:22px;height:22px;border-radius:5px;display:inline-flex;
  align-items:center;justify-content:center;border:1px solid var(--line);flex:none}
.gA{color:var(--green)}.gB{color:#9fd35f}.gC{color:var(--amber)}.gD{color:var(--high)}.gF{color:var(--crit)}
.sidefoot{padding:10px 16px;border-top:1px solid var(--line);color:var(--ink3);font-size:10.5px}
/* main */
.main{overflow:auto;min-height:0}
.wrap{max-width:1000px;margin:0 auto;padding:22px 26px 80px}
.hdr{display:grid;grid-template-columns:1fr auto;gap:18px;align-items:center;border:1px solid var(--line);
  border-radius:12px;background:linear-gradient(180deg,#0d131cd0,#0a0e14d0);padding:20px 22px}
.hdr .p{font-size:clamp(17px,2.6vw,26px);word-break:break-all}
.hdr .p .d{color:var(--green)}.hdr .p .h{color:var(--amber)}
.hdr .sub{color:var(--ink2);font-size:12px;margin-top:8px;display:flex;flex-wrap:wrap;gap:6px 16px}
.hdr .sub b{color:var(--ink)}
.ring{width:104px;height:104px;border-radius:13px;border:1px solid var(--line);background:#0a0e14;
  display:flex;flex-direction:column;align-items:center;justify-content:center}
.ring .g{font-size:46px;font-weight:800;line-height:1}
.ring .l{font-size:9.5px;letter-spacing:.2em;color:var(--ink3);text-transform:uppercase;margin-top:3px}
.dlbtn{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);background:var(--panel);
  color:var(--amber);padding:7px 13px;border-radius:8px;cursor:pointer;font-family:var(--mono);font-size:12px}
.dlbtn:hover{background:var(--panel2)}
.sec{margin:26px 0 11px;font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--ink3);
  display:flex;align-items:center;gap:10px}
.sec::before{content:"//";color:var(--amber)}.sec .rule{flex:1;height:1px;background:var(--line)}
.chips{display:flex;gap:8px;flex-wrap:wrap}
.chip{border:1px solid var(--line);border-radius:8px;padding:8px 13px;background:var(--panel);cursor:pointer;
  display:flex;align-items:center;gap:9px;position:relative;overflow:hidden}
.chip::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px}
.chip.critical::before{background:var(--crit)}.chip.high::before{background:var(--high)}
.chip.medium::before{background:var(--med)}.chip.low::before{background:var(--low)}.chip.info::before{background:var(--info)}
.chip .n{font-size:19px;font-weight:800;font-variant-numeric:tabular-nums}
.chip .k{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--ink2)}
.chip.off{opacity:.4}
.critical .n{color:var(--crit)}.high .n{color:var(--high)}.medium .n{color:var(--med)}.low .n{color:var(--low)}.info .n{color:var(--info)}
.stats{display:flex;gap:9px;flex-wrap:wrap;margin-top:12px}
.stat{border:1px solid var(--line);border-radius:9px;padding:9px 14px;background:var(--panel)}
.stat .n{font-size:18px;font-weight:700;color:var(--cyan)}.stat .k{font-size:10px;color:var(--ink3);text-transform:uppercase;letter-spacing:.1em}
/* findings */
.find{border:1px solid var(--line);border-radius:10px;background:var(--panel);margin-top:10px;overflow:hidden;position:relative}
.find::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px}
.find.critical::before{background:var(--crit)}.find.high::before{background:var(--high)}
.find.medium::before{background:var(--med)}.find.low::before{background:var(--low)}.find.info::before{background:var(--info)}
.fhead{padding:13px 16px 13px 19px;cursor:pointer;display:flex;gap:13px;align-items:flex-start}
.fhead:hover{background:var(--panel2)}
.pill{font-size:9.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;padding:3px 8px;border-radius:5px;
  white-space:nowrap;border:1px solid transparent}
.pill.critical{color:var(--crit);background:#ff53701a;border-color:#ff537055}
.pill.high{color:var(--high);background:#ff8f401a;border-color:#ff8f4055}
.pill.medium{color:var(--med);background:#ffb4541a;border-color:#ffb45455}
.pill.low{color:var(--low);background:#59c2ff1a;border-color:#59c2ff55}
.pill.info{color:var(--info);background:#6b7c8f1a;border-color:#6b7c8f55}
.ft{flex:1;min-width:0}.ft .t{color:var(--ink);font-weight:600;font-size:14px}
.ft .u{color:var(--ink2);font-size:11.5px;margin-top:4px;word-break:break-all}.ft .u .m{color:var(--amber);font-weight:700}
.ft .tags{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}
.tag{font-size:9.5px;color:var(--ink3);border:1px solid var(--line);border-radius:4px;padding:1px 6px}
.chev{color:var(--ink3);transition:transform .2s;margin-top:2px}.find.open .chev{transform:rotate(90deg)}
.fbody{display:none;padding:2px 16px 16px 19px;border-top:1px solid var(--line)}.find.open .fbody{display:block}
.blk{margin-top:14px}.blk .h{font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:var(--ink3);margin-bottom:7px}
.blk .h::before{content:"▸ ";color:var(--amber)}
.reason{color:var(--green);background:#0a1410;border:1px solid #17331f;border-radius:8px;padding:10px 13px;white-space:pre-wrap;word-break:break-word;font-size:12.5px}
.proof{display:grid;grid-template-columns:1fr 1fr;gap:11px}@media(max-width:820px){.proof{grid-template-columns:1fr}}
.pane{border:1px solid var(--line);border-radius:8px;overflow:hidden;background:var(--bg2)}
.pane .lbl{font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;padding:6px 11px;border-bottom:1px solid var(--line);color:var(--ink3);background:#0a0e14;display:flex;justify-content:space-between}
.pane pre{margin:0;padding:10px 12px;font-size:11px;line-height:1.5;white-space:pre-wrap;word-break:break-word;max-height:320px;overflow:auto}
.rq{color:var(--amber)}.s2{color:var(--green)}.s3{color:var(--cyan)}.s4,.s5{color:var(--crit)}
.mt{color:var(--ink3);font-size:10px}
.badge{font-size:9px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;padding:2px 6px;border-radius:5px;margin-left:6px;vertical-align:middle;border:1px solid var(--line)}
.badge.det{color:var(--cyan);background:#59c2ff14}
.badge.conf-confirmed{color:var(--green);background:#7fd96214;border-color:#7fd96255}
.badge.conf-firm{color:var(--amber);background:#ffb45414;border-color:#ffb45455}
.badge.conf-tentative{color:var(--ink2);background:#6b7c8f14}
pre.payload{margin:0;padding:10px 12px;background:#160f0a;border:1px solid #3a2a12;border-radius:8px;color:var(--amber);font-size:11.5px;white-space:pre-wrap;word-break:break-all;overflow:auto}
pre.repro{margin:0;padding:10px 12px;background:#0a1014;border:1px solid #16323f;border-radius:8px;color:var(--cyan);font-size:11px;white-space:pre-wrap;word-break:break-all;overflow:auto;user-select:all}
details.raw{border:1px solid var(--line);border-radius:8px;background:var(--bg2);overflow:hidden}
details.raw summary{cursor:pointer;padding:8px 12px;font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink3);list-style:none;user-select:none}
details.raw summary::-webkit-details-marker{display:none}
details.raw summary::before{content:"▸ ";color:var(--amber)}details.raw[open] summary::before{content:"▾ "}
details.raw pre{margin:0;padding:0 12px 12px;font-size:11px;color:var(--ink2);white-space:pre-wrap;word-break:break-word;max-height:400px;overflow:auto}
.exlabel{font-size:11px;color:var(--amber);margin:9px 0 4px;font-weight:600}
.empty{color:var(--ink3);text-align:center;padding:80px 20px}
.empty .big{font-size:40px;color:var(--amber2);margin-bottom:10px}
.exsep{font-size:10px;color:var(--ink3);margin:11px 0 3px}
</style></head><body>
<div class="app">
  <aside class="side">
    <div class="logo"><div class="b">▚ dast-ng</div><div class="s">web console</div></div>
    <div class="scans" id="scans"></div>
    <div class="sidefoot" id="sidefoot">loading…</div>
  </aside>
  <main class="main"><div class="wrap" id="main">
    <div class="empty"><div class="big">▚</div>select a scan on the left</div>
  </div></main>
</div>
<script>
const E=(t,c,h)=>{const e=document.createElement(t);if(c)e.className=c;if(h!=null)e.innerHTML=h;return e;};
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]));
const SEVS=['critical','high','medium','low','info'];
let SEL=null, DATA=null, FILTER=new Set(SEVS);

async function loadScans(){
  const r=await fetch('/api/scans'); const scans=await r.json();
  const box=document.getElementById('scans'); box.innerHTML='';
  document.getElementById('sidefoot').textContent=scans.length+' scan'+(scans.length===1?'':'s');
  if(!scans.length){box.appendChild(E('div','sidefoot','no scans yet — run: dastng launch -t <url>'));return;}
  scans.forEach(s=>{
    const it=E('div','scanitem'+(s.id===SEL?' sel':''));
    it.innerHTML=`<div class="t"><span class="gbadge g${s.grade}">${s.grade}</span><span>${esc(s.target)}</span></div>
      <div class="meta"><span>${s.findings} findings</span><span>${s.severities.critical+s.severities.high} hi/crit</span></div>`;
    it.onclick=()=>{SEL=s.id;loadScan(s.id);document.querySelectorAll('.scanitem').forEach(x=>x.classList.remove('sel'));it.classList.add('sel');};
    box.appendChild(it);
  });
  if(!SEL&&scans.length){SEL=scans[0].id;loadScan(SEL);box.firstChild.classList.add('sel');}
}
async function loadScan(id){
  const r=await fetch('/api/scan/'+id); DATA=await r.json(); FILTER=new Set(SEVS); render();
}
function render(){
  const d=DATA, s=d.summary, m=document.getElementById('main'); m.innerHTML='';
  const host=(s.target||'').replace(/^https?:\/\//,'').split('/')[0];
  const hdr=E('div','hdr');
  hdr.innerHTML=`<div>
    <div class="p"><span class="d">$</span> dastng scan <span class="h">${esc(host)}</span></div>
    <div class="sub"><span><b>${s.findings}</b> findings</span>
      <span>profile <b>${esc((d.policy&&d.policy.name)||'safe-deep')}</b></span>
      <span>crawl <b>${s.urls}</b> urls</span><span>targets <b>${s.targets}</b></span>
      ${d.session&&d.session.reauths?`<span>re-auths <b>${d.session.reauths}</b></span>`:''}</div>
    <a class="dlbtn" href="/api/report/${d.id}" target="_blank">⭳ download report</a></div>
    <div class="ring"><div class="g g${s.grade}">${s.grade}</div><div class="l">risk grade</div></div>`;
  m.appendChild(hdr);
  m.appendChild(E('div','sec','executive summary<span class="rule"></span>'));
  const chips=E('div','chips');
  SEVS.forEach(sv=>{const c=E('div','chip '+sv+(FILTER.has(sv)?'':' off'));
    c.innerHTML=`<span class="n">${s.severities[sv]}</span><span class="k">${sv}</span>`;
    c.onclick=()=>{FILTER.has(sv)?FILTER.delete(sv):FILTER.add(sv);if(!FILTER.size)FILTER=new Set(SEVS);render();};
    chips.appendChild(c);});
  m.appendChild(chips);
  m.appendChild(E('div','sec','findings<span class="rule"></span>'));
  const shown=d.findings.filter(f=>FILTER.has(f.severity));
  if(!shown.length){m.appendChild(E('div','empty','no findings for this filter'));return;}
  shown.forEach(f=>m.appendChild(renderFinding(f)));
}
function renderFinding(f){
  const el=E('div','find '+f.severity);
  const tags=[`<span class="tag">${esc(f.cwe)}</span>`,`<span class="tag">${esc(f.owasp)}</span>`,`<span class="tag">tool:${esc(f.tool)}</span>`];
  if(f.param)tags.unshift(`<span class="tag">param:${esc(f.param)}</span>`);
  let badges='';
  if(f.detection)badges+=`<span class="badge det">${esc(f.detection)}</span>`;
  if(f.confidence)badges+=`<span class="badge conf-${esc(f.confidence)}">${esc(f.confidence)}</span>`;
  const head=E('div','fhead');
  head.innerHTML=`<span class="pill ${f.severity}">${f.severity}</span>
    <div class="ft"><div class="t">${esc(f.vtitle)} ${badges}</div>
      <div class="u"><span class="m">${esc(f.method)}</span> ${esc(f.url)}</div>
      <div class="tags">${tags.join('')}</div></div><span class="chev">▸</span>`;
  head.onclick=()=>el.classList.toggle('open');
  const body=E('div','fbody');
  let h=`<div class="blk"><div class="h">Description</div><div>${esc(f.vdesc)}</div></div>`;
  const ev=f.evidence_log||[];
  if(f.evidence)h+=`<div class="blk"><div class="h">Reasoning</div><div class="reason">${esc(f.evidence)}</div></div>`;
  if(f.payload)h+=`<div class="blk"><div class="h">Payload</div><pre class="payload">${esc(f.payload)}</pre></div>`;
  if(ev.length){h+=`<div class="blk"><div class="h">Proof — request / response (${ev.length})</div>`;
    ev.forEach((x,i)=>{if(ev.length>1)h+=`<div class="exsep">exchange ${i+1} / ${ev.length}</div>`;h+=proof(x);});h+=`</div>`;}
  else if(!f.payload)h+=`<div class="blk"><div class="h">Evidence</div><div class="reason">${esc(f.evidence||('reported by '+f.tool))}</div></div>`;
  if(f.raw_output&&f.raw_output.trim().length>2)h+=`<div class="blk"><details class="raw"><summary>Raw tool output (${esc(f.tool)})</summary><pre>${esc(f.raw_output)}</pre></details></div>`;
  if(f.repro)h+=`<div class="blk"><div class="h">Reproduce</div><pre class="repro">${esc(f.repro)}</pre></div>`;
  h+=`<div class="blk"><div class="h">Remediation</div><div>${esc(f.vfix)}</div></div>`;
  body.innerHTML=h; el.appendChild(head); el.appendChild(body); return el;
}
function proof(x){
  const rq=x.request||{},rs=x.response||{};
  const hdr=o=>Object.entries(o||{}).map(([k,v])=>esc(k)+': '+esc(v)).join('\n');
  let req=`<span class="rq">${esc(rq.method||'GET')} ${esc(rq.url||'')}</span>\n`+hdr(rq.headers);
  if(rq.body)req+='\n\n'+esc(rq.body);
  const st=rs.status||0, sc='s'+String(st)[0];
  const mt=[rs.elapsed_ms!=null?rs.elapsed_ms+' ms':'',rs.size!=null?rs.size+' B':''].filter(Boolean).join(' · ');
  let resp=`<span class="${sc}">HTTP ${esc(st)}</span>  <span class="mt">${esc(mt)}</span>\n`+hdr(rs.headers)+'\n\n'+esc(rs.body||'')+(rs.truncated?'\n\n[response truncated]':'');
  const lbl=x.label?`<div class="exlabel">▸ ${esc(x.label)}</div>`:'';
  return `${lbl}<div class="proof"><div class="pane"><div class="lbl">Request<span>attack</span></div><pre>${req}</pre></div>
    <div class="pane"><div class="lbl">Response<span>evidence</span></div><pre>${resp}</pre></div></div>`;
}
loadScans(); setInterval(loadScans, 15000);
</script></body></html>
"""
