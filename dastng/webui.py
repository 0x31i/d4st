"""The dast-ng web console single-page app (served by server.py at /).

Vanilla JS against the DB-backed JSON API (no build step, no framework). Terminal/hacker
aesthetic: deep ink ground, amber accent, monospace, severity stripes. NO grade — this is an
observability tool. Seven surfaces: Overview, Findings (+ triage write-back), Attack Surface,
Engines, Timeline, Evidence, and Raw Data (the ASM-NG-style Excel-filter power grid).
See docs/console-build-plan.md.
"""

INDEX_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>dast-ng console</title>
<style>
:root{
  --bg:#070a0f;--bg2:#0b0f16;--panel:#0d131c;--panel2:#111925;--line:#1c2733;--line2:#243243;
  --ink:#d7e0ea;--ink2:#8595a6;--ink3:#5b6b7c;
  --amber:#ffb454;--amber2:#f0a020;--green:#7fd962;--cyan:#59c2ff;--violet:#b48ef0;
  --crit:#ff5370;--high:#ff8f40;--med:#ffb454;--low:#59c2ff;--info:#6b7c8f;
  --mono:"SF Mono","JetBrains Mono",ui-monospace,"Cascadia Code",Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--ink);font-family:var(--mono);font-size:13px;line-height:1.5;
  -webkit-font-smoothing:antialiased;overflow:hidden;
  background-image:radial-gradient(1100px 560px at 88% -12%,#12202e40,transparent 62%),
    radial-gradient(700px 400px at 5% 108%,#1a141e30,transparent 60%);}
a{color:var(--cyan);text-decoration:none}
::selection{background:var(--amber);color:#0a0a0a}
::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:#1d2836;border-radius:6px}
::-webkit-scrollbar-track{background:transparent}
.app{display:grid;grid-template-columns:264px 1fr;height:100vh}
.side{border-right:1px solid var(--line);background:linear-gradient(180deg,var(--bg2),#080b11);display:flex;flex-direction:column;min-height:0}
.logo{padding:16px 18px 14px;border-bottom:1px solid var(--line)}
.logo .b{font-weight:800;letter-spacing:.30em;color:var(--amber);text-transform:uppercase;font-size:12.5px;display:flex;align-items:center;gap:8px}
.logo .b .dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green)}
.logo .s{color:var(--ink3);font-size:10.5px;margin-top:5px;letter-spacing:.04em}
.scanhead{padding:12px 16px 6px;color:var(--ink3);font-size:9.5px;letter-spacing:.22em;text-transform:uppercase;display:flex;justify-content:space-between;align-items:center}
.scans{overflow:auto;flex:1;padding:2px 8px 8px}
.scanitem{padding:10px 12px;border:1px solid transparent;border-radius:9px;cursor:pointer;margin-bottom:5px;transition:background .12s,border-color .12s}
.scanitem:hover{background:var(--panel)}
.scanitem.sel{background:var(--panel2);border-color:var(--line2)}
.scanitem .t{color:var(--ink);font-size:12.5px;display:flex;align-items:center;gap:9px}
.scanitem .t .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.scanitem .meta{color:var(--ink3);font-size:10.5px;margin-top:6px;display:flex;gap:12px;flex-wrap:wrap}
.scanitem .meta b{color:var(--ink2);font-weight:600}
.sevmark{width:9px;height:9px;border-radius:3px;flex:none}
.m-crit{background:var(--crit);box-shadow:0 0 7px #ff537066}.m-high{background:var(--high);box-shadow:0 0 7px #ff8f4066}
.m-med{background:var(--med)}.m-low{background:var(--low)}.m-info{background:var(--info)}.m-none{background:var(--ink3)}
.live{font-size:9px;color:var(--green);border:1px solid #2a4a2f;background:#12211533;padding:1px 6px;border-radius:20px;display:inline-flex;align-items:center;gap:5px}
.live .p{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 1.3s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
.sidefoot{padding:11px 16px;border-top:1px solid var(--line);color:var(--ink3);font-size:10px;display:flex;justify-content:space-between}
.sidefoot b{color:var(--ink2)}
.main{overflow:auto;min-height:0}
.wrap{max-width:1180px;margin:0 auto;padding:20px 26px 90px}
.hdr{display:grid;grid-template-columns:1fr auto;gap:20px;align-items:center;border:1px solid var(--line);
  border-radius:13px;background:linear-gradient(180deg,#0d131cdd,#0a0e14dd);padding:18px 22px}
.hdr .p{font-size:19px;word-break:break-all;letter-spacing:.01em}
.hdr .p .sc{color:var(--ink3)}.hdr .p .d{color:var(--green)}.hdr .p .h{color:var(--amber)}
.hdr .sub{color:var(--ink2);font-size:11.5px;margin-top:9px;display:flex;flex-wrap:wrap;gap:6px 18px}
.hdr .sub b{color:var(--ink)}.hdr .sub .k{color:var(--ink3)}
.hdrright{display:flex;flex-direction:column;align-items:flex-end;gap:12px}
.exportwrap{position:relative}
.exportbtn{font-family:var(--mono);font-size:11.5px;font-weight:700;letter-spacing:.08em;color:var(--amber);
  background:linear-gradient(180deg,#161f2b,#0e151e);border:1px solid var(--line2);border-radius:8px;
  padding:8px 13px;cursor:pointer;transition:border-color .12s,color .12s}
.exportbtn:hover{border-color:var(--amber2);color:var(--amber2)}
.exportmenu{display:none;position:absolute;right:0;top:38px;z-index:50;width:262px;
  background:#0c1420;border:1px solid var(--line2);border-radius:11px;padding:7px;
  box-shadow:0 18px 44px -14px rgba(0,0,0,.75)}
.exportmenu.on{display:block}
.exportmenu .emhead{font-size:9px;letter-spacing:.16em;text-transform:uppercase;color:var(--ink3);padding:7px 10px 5px}
.exportmenu a{display:block;font-size:12.5px;color:var(--ink);padding:9px 10px;border-radius:7px;cursor:pointer;text-decoration:none}
.exportmenu a:hover{background:var(--panel2);color:var(--amber)}
.exportmenu .emnote{font-size:10.5px;color:var(--ink3);padding:8px 10px 4px;line-height:1.4;border-top:1px solid var(--line);margin-top:4px}
.donut{width:100px;height:100px;border-radius:50%;flex:none;position:relative}
.donut::after{content:"";position:absolute;inset:11px;border-radius:50%;background:radial-gradient(circle at 50% 34%,#101822,#0a0e14);border:1px solid var(--line)}
.donut .in{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:1}
.donut .n{font-size:32px;font-weight:800;line-height:1;color:var(--ink)}
.donut .l{font-size:8.5px;letter-spacing:.2em;color:var(--ink3);text-transform:uppercase;margin-top:3px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:14px}
.stat{border:1px solid var(--line);border-radius:10px;background:var(--panel);padding:11px 13px;position:relative;overflow:hidden;cursor:pointer}
.stat:hover{border-color:var(--line2)}
.stat::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px}
.stat.crit::before{background:var(--crit)}.stat.high::before{background:var(--high)}
.stat.med::before{background:var(--med)}.stat.low::before{background:var(--low)}.stat.info::before{background:var(--info)}
.stat .n{font-size:24px;font-weight:800;line-height:1}
.stat .l{font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink3);margin-top:5px}
.stat.crit .n{color:var(--crit)}.stat.high .n{color:var(--high)}.stat.med .n{color:var(--med)}.stat.low .n{color:var(--low)}.stat.info .n{color:var(--ink2)}
.tabbar{display:flex;gap:3px;margin:22px 0 0;border-bottom:1px solid var(--line);flex-wrap:wrap}
.tab{padding:9px 15px;font-size:12px;color:var(--ink3);cursor:pointer;border:1px solid transparent;border-bottom:none;
  border-radius:8px 8px 0 0;display:flex;align-items:center;gap:8px;letter-spacing:.03em;transition:color .12s,background .12s}
.tab:hover{color:var(--ink2)}
.tab.on{color:var(--amber);background:var(--panel);border-color:var(--line);position:relative;top:1px}
.tab .c{font-size:10px;color:var(--ink3);background:#0a0e14;border:1px solid var(--line2);border-radius:10px;padding:0 6px;min-width:20px;text-align:center}
.tab.on .c{color:var(--amber2)}
.panel{display:none;padding-top:18px}.panel.on{display:block}
.toolbar{display:flex;gap:9px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
.search{flex:1;min-width:200px;position:relative}
.search input{width:100%;background:var(--panel);border:1px solid var(--line2);border-radius:8px;color:var(--ink);
  font-family:var(--mono);font-size:12px;padding:8px 12px 8px 30px;outline:none}
.search input:focus{border-color:var(--amber2)}
.search::before{content:"\2315";position:absolute;left:11px;top:7px;color:var(--ink3);font-size:14px}
.fpill{font-size:11px;padding:6px 11px;border:1px solid var(--line2);border-radius:8px;background:var(--panel);color:var(--ink2);cursor:pointer;display:flex;align-items:center;gap:7px}
.fpill:hover{border-color:var(--amber2);color:var(--ink)}.fpill .dot{width:8px;height:8px;border-radius:2px}.fpill.off{opacity:.4}
.tbl{width:100%;border-collapse:separate;border-spacing:0;border:1px solid var(--line);border-radius:11px;overflow:hidden}
.tbl thead th{background:#0a0e14;color:var(--ink3);font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;
  text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);font-weight:600;cursor:pointer;user-select:none;white-space:nowrap}
.tbl thead th:hover{color:var(--ink2)}.tbl thead th .ar{color:var(--amber2);font-size:9px}
.tbl tbody tr{border-bottom:1px solid #131c26}
.tbl tbody tr.row{cursor:pointer;transition:background .1s}.tbl tbody tr.row:hover{background:#0e1620}
.tbl td{padding:9px 12px;vertical-align:middle;font-size:12px}
.sevcell{display:inline-flex;align-items:center;gap:8px;font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.sevcell .bar{width:3px;height:15px;border-radius:2px}
.sev-critical{color:var(--crit)}.sev-critical .bar{background:var(--crit)}
.sev-high{color:var(--high)}.sev-high .bar{background:var(--high)}
.sev-medium{color:var(--med)}.sev-medium .bar{background:var(--med)}
.sev-low{color:var(--low)}.sev-low .bar{background:var(--low)}
.sev-info{color:var(--info)}.sev-info .bar{background:var(--info)}
.cat{color:var(--ink)}.mut{color:var(--ink3)}
.url{color:var(--cyan);font-size:11.5px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:middle}
.chiptool{font-size:10px;color:var(--ink2);background:#0a0e14;border:1px solid var(--line2);border-radius:5px;padding:1px 7px}
.vbadge{font-size:9.5px;font-weight:700;padding:2px 8px;border-radius:20px;letter-spacing:.06em;text-transform:uppercase}
.v-yes{color:var(--green);border:1px solid #2c4a30;background:#12211533}
.v-no{color:var(--high);border:1px solid #4a3320;background:#22160a33}
.v-un{color:var(--ink3);border:1px solid var(--line2);background:#0a0e14}
.tstat{font-size:9.5px;font-weight:700;padding:2px 8px;border-radius:20px;letter-spacing:.05em;text-transform:uppercase;border:1px solid var(--line2);color:var(--ink3)}
.tstat.confirmed{color:var(--green);border-color:#2c4a30}.tstat.false_positive{color:var(--crit);border-color:#4a2020}
.tstat.accepted{color:var(--cyan);border-color:#123040}
.detail{background:#090d13;border-bottom:1px solid var(--line)}.detail td{padding:0}
.dgrid{display:grid;grid-template-columns:1.15fr .85fr;gap:14px;padding:16px 18px}
.dcard{border:1px solid var(--line);border-radius:9px;background:var(--panel);overflow:hidden}
.dcard .h{font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--ink3);padding:9px 12px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:8px}
.dcard .h .ic{color:var(--amber2)}
.dcard .bd{padding:11px 13px;font-size:11.5px;color:var(--ink2)}
.dcard.warn{border-color:#3a2a12}.dcard.warn .h{color:var(--amber)}
.kv{display:flex;gap:8px;margin:3px 0}.kv .k{color:var(--ink3);min-width:78px}.kv .v{color:var(--ink)}
.code{background:#05080c;border:1px solid var(--line);border-radius:7px;padding:9px 11px;font-size:11px;color:var(--green);
  white-space:pre-wrap;word-break:break-all;margin-top:4px;line-height:1.5;max-height:220px;overflow:auto}
.code .st{color:var(--amber)}
.remedy{color:var(--ink2)}.remedy b{color:var(--ink)}
.actions{display:flex;gap:8px;padding:11px 18px 16px;border-top:1px solid #131c26;align-items:center;flex-wrap:wrap}
.abtn{font-size:11px;padding:7px 13px;border-radius:8px;border:1px solid var(--line2);background:var(--panel);color:var(--ink2);cursor:pointer;display:flex;align-items:center;gap:7px}
.abtn:hover{border-color:var(--amber2);color:var(--ink)}
.abtn.ok:hover{border-color:#2c4a30;color:var(--green)}.abtn.fp:hover{border-color:#4a2020;color:var(--crit)}.abtn.ac:hover{border-color:#123040;color:var(--cyan)}
.abtn.on-ok{border-color:#2c4a30;color:var(--green)}.abtn.on-fp{border-color:#4a2020;color:var(--crit)}.abtn.on-ac{border-color:#123040;color:var(--cyan)}
.notebox{flex:1;min-width:180px;display:flex;gap:7px}
.notebox input{flex:1;background:#0d131c;border:1px solid var(--line2);border-radius:7px;color:var(--ink);font-family:var(--mono);font-size:11px;padding:6px 9px;outline:none}
.notebox input:focus{border-color:var(--amber2)}
.enrow{display:grid;grid-template-columns:160px 70px 1fr auto;gap:14px;align-items:center;padding:11px 14px;border:1px solid var(--line);border-radius:9px;background:var(--panel);margin-bottom:7px}
.enrow .en{color:var(--ink);font-size:12.5px;display:flex;align-items:center;gap:9px}
.enrow .st{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em}
.st-ran{color:var(--green)}.st-skip{color:var(--ink3)}.st-miss{color:var(--crit)}
.enrow .nt{color:var(--ink2);font-size:11.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.enrow .fc{color:var(--amber);font-size:11px;font-weight:700}
.dotg{width:8px;height:8px;border-radius:50%;flex:none}.dotg.g{background:var(--green);box-shadow:0 0 7px var(--green)}.dotg.m{background:var(--crit)}
.tl{position:relative;padding-left:22px;margin-top:4px}
.tl::before{content:"";position:absolute;left:6px;top:4px;bottom:4px;width:1px;background:var(--line2)}
.tlrow{position:relative;padding:8px 0 8px 4px;display:flex;gap:14px;align-items:baseline}
.tlrow::before{content:"";position:absolute;left:-19px;top:13px;width:9px;height:9px;border-radius:50%;background:var(--panel2);border:2px solid var(--amber2)}
.tlrow.warn::before{border-color:var(--crit)}
.tlrow .ts{color:var(--ink3);font-size:10.5px;min-width:60px;font-variant-numeric:tabular-nums}
.tlrow .ms{color:var(--ink);font-size:12px}.tlrow .ms .sub{color:var(--ink3);font-size:10.5px}
.tlrow.warn .ms{color:var(--amber)}
.srcbadge{font-size:10px;color:var(--violet);background:#160f2233;border:1px solid #2e2340;border-radius:5px;padding:1px 7px}
.hit-y{color:var(--crit);font-weight:700}.hit-n{color:var(--ink3)}.tgt-y{color:var(--amber)}.tgt-n{color:var(--ink3)}
.rawbar{display:flex;gap:9px;align-items:center;margin-bottom:10px;flex-wrap:wrap}
.rawbar .cnt{color:var(--ink3);font-size:11px;margin-left:auto}.rawbar .cnt b{color:var(--amber2)}
.rawbar .clr{font-size:11px;color:var(--ink3);cursor:pointer;border:1px solid var(--line2);border-radius:7px;padding:6px 10px}
.rawbar .clr:hover{color:var(--ink);border-color:var(--amber2)}
.rtbl{width:100%;border-collapse:separate;border-spacing:0;border:1px solid var(--line);border-radius:11px;overflow:hidden;table-layout:fixed}
.rtbl thead th{background:#0a0e14;color:var(--ink3);font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;
  text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);font-weight:600;cursor:pointer;user-select:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rtbl thead th:hover{color:var(--ink2)}.rtbl thead th .ar{color:var(--amber2);font-size:9px;margin-left:3px}
.rtbl thead tr.filt th{padding:5px 7px;cursor:auto;background:#080b10}
.rf-input,.rf-select{width:100%;background:#0d131c;border:1px solid var(--line2);border-radius:6px;color:var(--ink);
  font-family:var(--mono);font-size:10.5px;padding:4px 6px;outline:none}
.rf-input:focus,.rf-select:focus{border-color:var(--amber2)}.rf-input::placeholder{color:#44525f}
.rf-select{cursor:pointer}.rf-select.on{border-color:var(--amber2);color:var(--amber)}
.rtbl tbody tr{border-bottom:1px solid #111a24}.rtbl tbody tr:hover{background:#0e1620}
.rtbl td{padding:7px 10px;font-size:11.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.kb{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:2px 7px;border-radius:5px;border:1px solid}
.kb-finding{color:var(--amber);border-color:#3a2a12;background:#1a120633}
.kb-url{color:var(--violet);border-color:#2e2340;background:#160f2233}
.kb-probe{color:var(--green);border-color:#20321f;background:#0f1e1033}
.kb-exchange{color:var(--cyan);border-color:#123040;background:#0a1c2833}
.kb-event{color:var(--ink2);border-color:var(--line2);background:#0a0e14}
.rtbl .u{color:var(--cyan)}.rtbl .m{color:var(--ink3)}
.rtbl .sv-critical{color:var(--crit);font-weight:700}.rtbl .sv-high{color:var(--high);font-weight:700}
.rtbl .sv-medium{color:var(--med)}.rtbl .sv-low{color:var(--low)}.rtbl .sv-info{color:var(--info)}
.note{color:var(--ink3);font-size:11px;margin:16px 2px 0;padding:12px 14px;border:1px dashed var(--line2);border-radius:9px;background:#0a0e1466}
.note b{color:var(--amber2)}
.empty{color:var(--ink3);text-align:center;padding:40px 20px;font-size:12px}
.livebar{margin:14px 0 0;padding:10px 14px;border:1px solid #2a4a2f;border-radius:9px;background:#12211522;color:var(--green);font-size:11.5px;display:flex;align-items:center;gap:10px}
.toast{position:fixed;bottom:20px;right:20px;z-index:100;background:rgba(6,78,59,.95);border:1px solid rgba(52,211,153,.45);
  color:#d1fae5;font-size:12px;padding:10px 14px;border-radius:9px;box-shadow:0 12px 34px -12px rgba(0,0,0,.7);opacity:0;transition:opacity .2s}
.toast.show{opacity:1}.toast.err{background:rgba(127,29,29,.95);border-color:rgba(239,68,68,.45);color:#fee2e2}
.spin{color:var(--ink3);padding:30px;text-align:center}
</style></head><body>
<div class="app">
  <aside class="side">
    <div class="logo"><div class="b"><span class="dot"></span>dast-ng</div><div class="s">observability console</div></div>
    <div class="scanhead"><span>Scans</span><span id="scancount" style="color:var(--ink3)"></span></div>
    <div class="scans" id="scans"></div>
    <div class="sidefoot"><span id="dbinfo">SQLite</span><span id="portinfo"></span></div>
  </aside>
  <main class="main"><div class="wrap" id="wrap">
    <div class="spin" id="boot">loading…</div>
    <div id="content" style="display:none">
      <div class="hdr">
        <div>
          <div class="p" id="hdrp"></div>
          <div class="sub" id="hdrsub"></div>
        </div>
        <div class="hdrright">
          <div class="exportwrap">
            <button class="exportbtn" id="exportbtn">↧ EXPORT ▾</button>
            <div class="exportmenu" id="exportmenu">
              <div class="emhead">Client report</div>
              <a id="ex-html" target="_blank">Open full report (HTML)</a>
              <a id="ex-pdf">Download full PDF</a>
              <a id="ex-pdfc">Download concise PDF</a>
              <div class="emnote">Concise caps giant response bodies on low-severity findings; critical &amp; high keep full evidence.</div>
            </div>
          </div>
          <div class="donut" id="donut"><div class="in"><div class="n" id="donutn">0</div><div class="l">findings</div></div></div>
        </div>
      </div>
      <div class="stats" id="stats"></div>
      <div id="livebar"></div>
      <div class="tabbar" id="tabbar"></div>
      <div id="panels"></div>
    </div>
  </div></main>
</div>
<div class="toast" id="toast"></div>
<script>
const API = "";
const SEV=["critical","high","medium","low","info"];
const SEVN={critical:0,high:1,medium:2,low:3,info:4};
const TABS=[["overview","Overview"],["findings","Findings"],["surface","Attack Surface"],
  ["engines","Engines"],["timeline","Timeline"],["evidence","Evidence"],["raw","Raw Data"]];
let SCAN=null, OV=null, TAB="overview";
let FINDINGS=[], fSev=new Set(["critical","high","medium","low"]), fQ="", fSort="severity", fDir=1, fOpen=null;
let RAW=[], rfilt={}, rQ="", rSort="", rDir=1;
let livtimer=null;

const esc=s=>String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
async function api(p,opt){const r=await fetch(API+p,opt);if(!r.ok)throw new Error(r.status+" "+p);return r.json();}
function toast(m,err){const t=document.getElementById("toast");t.textContent=m;t.className="toast show"+(err?" err":"");setTimeout(()=>t.className="toast",2600);}
function ago(ts){if(!ts)return"";const s=Math.floor(Date.now()/1000)-ts;if(s<60)return s+"s ago";if(s<3600)return Math.floor(s/60)+"m ago";if(s<86400)return Math.floor(s/3600)+"h ago";return Math.floor(s/86400)+"d ago";}
function host(u){try{return new URL(u).host||u}catch(e){return u||""}}
function donutStops(sv){const tot=SEV.reduce((a,s)=>a+(sv[s]||0),0);if(!tot)return"var(--line2) 0 360deg";
  const col={critical:"var(--crit)",high:"var(--high)",medium:"var(--med)",low:"var(--low)",info:"var(--info)"};
  let acc=0,out=[];for(const s of SEV){const n=sv[s]||0;if(!n)continue;const a=acc/tot*360;acc+=n;out.push(`${col[s]} ${a.toFixed(2)}deg ${(acc/tot*360).toFixed(2)}deg`);}return out.join(",");}

// ---------- sidebar ----------
async function loadScans(){
  const scans=await api("/api/scans");
  document.getElementById("scancount").textContent=scans.length;
  const topSev=s=>{for(const k of SEV)if(s["sev_"+k])return k;return"none";};
  const sc=n=>({critical:"crit",high:"high",medium:"med",low:"low",info:"info",none:"none"}[n]);
  document.getElementById("scans").innerHTML=scans.map(s=>{
    const live=s.status==="in-progress";
    const worst=topSev(s), n=s["sev_"+worst]||0;
    const badge=live?'<span class="live"><span class="p"></span>scanning</span>':`<span><b>${s.n_findings}</b> findings</span>`;
    const wsev=worst!=="none"?`<span style="color:var(--${sc(worst)==='crit'?'crit':sc(worst)})">${n} ${worst.slice(0,4)}</span>`:"";
    return `<div class="scanitem${s.id===SCAN?" sel":""}" data-id="${esc(s.id)}">
      <div class="t"><span class="sevmark m-${sc(worst)}"></span><span class="nm">${esc(s.id)} · ${esc(host(s.target))}</span></div>
      <div class="meta">${badge}${wsev}<span>${ago(s.created_at)}</span></div></div>`;
  }).join("")||'<div class="empty">no scans ingested yet<br><span style="color:var(--ink3)">run: dast-ng ingest scan.json</span></div>';
  document.querySelectorAll(".scanitem").forEach(el=>el.onclick=()=>selectScan(el.dataset.id));
  if(!SCAN&&scans.length)selectScan(scans[0].id);
  return scans;
}

// ---------- scan header + tabs ----------
async function selectScan(id){
  SCAN=id; fOpen=null;
  document.querySelectorAll(".scanitem").forEach(e=>e.classList.toggle("sel",e.dataset.id===id));
  document.getElementById("boot").style.display="none";
  document.getElementById("content").style.display="block";
  OV=await api("/api/scans/"+encodeURIComponent(id));
  renderHeader();
  renderTabs();
  FINDINGS=await api(`/api/scans/${encodeURIComponent(id)}/findings?size=2000`);
  RAW=null;
  switchTab(TAB);
  clearInterval(livtimer);
  if(OV.status==="in-progress"){livtimer=setInterval(pollLive,2500);pollLive();}
}
function renderHeader(){
  const sv={critical:OV.sev_critical,high:OV.sev_high,medium:OV.sev_medium,low:OV.sev_low,info:OV.sev_info};
  document.getElementById("hdrp").innerHTML=`<span class="sc">scan </span><span class="d">${esc(OV.id)}</span> · <span class="h">${esc(OV.target)}</span>`;
  const reau=OV.reauths?`<b style="color:var(--high)">${OV.reauths} reauth${OV.reauths>1?"s":""}${OV.authed_at_end?"":" · dropped at end"}</b>`:"<b>clean</b>";
  document.getElementById("hdrsub").innerHTML=
    `<span><span class="k">profile</span> <b>${esc(OV.profile||"—")}</b></span>`+
    `<span><span class="k">crawl</span> <b>${OV.urls_count} urls</b></span>`+
    `<span><span class="k">targets</span> <b>${OV.targets_count}</b></span>`+
    `<span><span class="k">engines</span> <b>${(OV.engines||[]).filter(e=>e.ran).length}/${(OV.engines||[]).length} fired</b></span>`+
    (OV.sqlmap_level?`<span><span class="k">sqlmap</span> <b>level ${OV.sqlmap_level}</b></span>`:"")+
    `<span><span class="k">session</span> ${reau}</span>`;
  document.getElementById("donut").style.background="conic-gradient("+donutStops(sv)+")";
  document.getElementById("donutn").textContent=OV.n_findings;
  document.getElementById("stats").innerHTML=SEV.map(s=>{
    const c={critical:"crit",high:"high",medium:"med",low:"low",info:"info"}[s];
    return `<div class="stat ${c}" data-sev="${s}"><div class="n">${sv[s]||0}</div><div class="l">${s}</div></div>`;
  }).join("");
  document.querySelectorAll(".stat").forEach(el=>el.onclick=()=>{
    fSev=new Set([el.dataset.sev]);switchTab("findings");
  });
  wireExport();
}
function wireExport(){
  const id=encodeURIComponent(SCAN);
  document.getElementById("ex-html").href="/api/report/"+id;
  document.getElementById("ex-pdf").onclick=()=>{location.href="/api/report/"+id+"/pdf";document.getElementById("exportmenu").classList.remove("on");toast("building PDF…");};
  document.getElementById("ex-pdfc").onclick=()=>{location.href="/api/report/"+id+"/pdf?concise=1";document.getElementById("exportmenu").classList.remove("on");toast("building concise PDF…");};
}
function renderTabs(){
  const cnt={overview:"",findings:OV.n_findings,surface:OV.urls_count,engines:(OV.engines||[]).length,
    timeline:"",evidence:OV.exchanges_count,raw:""};
  document.getElementById("tabbar").innerHTML=TABS.map(([k,l])=>
    `<div class="tab${k===TAB?" on":""}" data-t="${k}">${l}${cnt[k]!==""?`<span class="c">${cnt[k]}</span>`:""}</div>`).join("");
  document.querySelectorAll(".tab").forEach(el=>el.onclick=()=>switchTab(el.dataset.t));
  document.getElementById("panels").innerHTML='<div id="panel"></div>';
}
function switchTab(t){
  TAB=t;document.querySelectorAll(".tab").forEach(e=>e.classList.toggle("on",e.dataset.t===t));
  const p=document.getElementById("panel");p.innerHTML='<div class="spin">…</div>';
  ({overview:renderOverview,findings:renderFindings,surface:renderSurface,engines:renderEngines,
    timeline:renderTimeline,evidence:renderEvidence,raw:renderRaw}[t])(p);
}

// ---------- OVERVIEW ----------
function renderOverview(p){
  const s=OV;
  p.innerHTML=`<div class="dgrid" style="grid-template-columns:1fr 1fr;padding:0;gap:14px">
    <div class="dcard"><div class="h"><span class="ic">◈</span> Coverage</div><div class="bd">
      <div class="kv"><span class="k">URLs crawled</span><span class="v">${s.urls_count}</span></div>
      <div class="kv"><span class="k">Injection targets</span><span class="v">${s.targets_count}</span></div>
      <div class="kv"><span class="k">Exchanges</span><span class="v">${s.exchanges_count}</span></div>
      <div class="kv"><span class="k">App</span><span class="v">${esc(s.app_type||"—")}</span></div>
      <div class="kv"><span class="k">Status</span><span class="v">${esc(s.status)}</span></div></div></div>
    <div class="dcard ${s.reauths||!s.authed_at_end?"warn":""}"><div class="h"><span class="ic">${s.reauths||!s.authed_at_end?"⚠":"✓"}</span> Session health</div><div class="bd">
      <div class="kv"><span class="k">SessionKeeper</span><span class="v" style="color:var(--green)">${s.session_keeper?"on":"off"}</span></div>
      <div class="kv"><span class="k">Re-auths</span><span class="v" style="color:${s.reauths?"var(--amber)":"var(--ink)"}">${s.reauths} mid-scan</span></div>
      <div class="kv"><span class="k">Authed at end</span><span class="v" style="color:${s.authed_at_end?"var(--green)":"var(--high)"}">${s.authed_at_end?"yes":"no — session lost"}</span></div>
      <div class="kv"><span class="k">Halted</span><span class="v">${s.halted?"yes":"no · ran full (stage "+s.stage+")"}</span></div></div></div></div>
    <div class="note">Executive read — every severity stat above is a drill-in to its filtered Findings view.</div>`;
}

// ---------- FINDINGS ----------
function vbadge(v){return v===1||v===true?'<span class="vbadge v-yes">verified</span>':v===0||v===false?'<span class="vbadge v-no">unconfirmed</span>':'<span class="vbadge v-un">—</span>';}
function tbadge(t){return t&&t!=="open"?`<span class="tstat ${t}">${t.replace("_"," ")}</span>`:"";}
function renderFindings(p){
  p.innerHTML=`<div class="toolbar">
      <div class="search"><input id="fq" placeholder="filter findings — category, url, param, tool…" value="${esc(fQ)}"></div>
      ${SEV.map(s=>`<div class="fpill${fSev.has(s)?"":" off"}" data-sev="${s}"><span class="dot" style="background:var(--${s==='critical'?'crit':s==='medium'?'med':s})"></span>${s[0].toUpperCase()+s.slice(1)}</div>`).join("")}
    </div>
    <table class="tbl" id="ftbl"><thead><tr>
      <th data-s="severity">Severity</th><th data-s="category">Category</th><th data-s="tool">Engine</th>
      <th data-s="url">URL</th><th data-s="param">Param</th><th data-s="verified">Status</th>
    </tr></thead><tbody id="fbody"></tbody></table>
    <div class="note">Indexed SQLite query — filter/sort/search stays instant. Expand a row for evidence, request/response proof, and one-click triage.</div>`;
  document.getElementById("fq").oninput=e=>{fQ=e.target.value.toLowerCase();fbody();};
  p.querySelectorAll(".fpill").forEach(el=>el.onclick=()=>{const s=el.dataset.sev;fSev.has(s)?fSev.delete(s):fSev.add(s);el.classList.toggle("off");fbody();});
  p.querySelectorAll("#ftbl thead th").forEach(th=>th.onclick=()=>{const k=th.dataset.s;if(fSort===k)fDir*=-1;else{fSort=k;fDir=1;}fbody();});
  fbody();
}
function fbody(){
  let rows=FINDINGS.filter(f=>fSev.has(f.severity)).filter(f=>!fQ||(f.category+f.url+f.param+f.tool+f.vtitle).toLowerCase().includes(fQ));
  rows.sort((a,b)=>{let x,y;if(fSort==="severity"){x=SEVN[a.severity];y=SEVN[b.severity];}else if(fSort==="verified"){x=a.verified===1?0:a.verified===0?1:2;y=b.verified===1?0:b.verified===0?1:2;}else{x=(a[fSort]||"")+"";y=(b[fSort]||"")+"";}return(x<y?-1:x>y?1:0)*fDir;});
  const body=document.getElementById("fbody");if(!body)return;
  body.innerHTML=rows.map(f=>`<tr class="row" data-id="${f.id}">
    <td><span class="sevcell sev-${f.severity}"><span class="bar"></span>${f.severity}</span></td>
    <td><span class="cat">${esc(f.vtitle)}</span><br><span class="mut" style="font-size:10px">${esc(f.category)}</span></td>
    <td><span class="chiptool">${esc(f.tool)}</span></td>
    <td><span class="url" title="${esc(f.url)}">${esc(f.url)}</span></td>
    <td>${f.param?esc(f.param):'<span class="mut">—</span>'}</td>
    <td>${vbadge(f.verified)} ${tbadge(f.triage_status)}</td></tr>
    <tr class="detail" id="d${f.id}" style="display:none"><td colspan="6"><div class="spin">…</div></td></tr>`).join("")
    ||'<tr><td colspan="6"><div class="empty">no findings match these filters</div></td></tr>';
  body.querySelectorAll("tr.row").forEach(r=>r.onclick=()=>toggleFinding(+r.dataset.id));
}
async function toggleFinding(id){
  const d=document.getElementById("d"+id);if(!d)return;
  if(d.style.display!=="none"){d.style.display="none";fOpen=null;return;}
  fOpen=id;d.style.display="";
  const f=await api("/api/findings/"+id);
  const exs=(f.evidence_log||[]).map(e=>`<div class="code">${esc(e.request.method||"")} ${esc(e.request.url||"")}${e.request.body?"\n"+esc(e.request.body):""}</div>
    <div class="code" style="color:var(--ink2)"><span class="st">HTTP ${e.response.status==null?"—":e.response.status}${e.response.elapsed_ms!=null?"  ("+e.response.elapsed_ms+"ms)":""}</span>${e.response.body?"\n"+esc((e.response.body||"").slice(0,400)):""}</div>`).join("")||'<div class="mut">no captured exchanges for this finding</div>';
  const on=s=>f.triage_status===s?" on-"+({confirmed:"ok",false_positive:"fp",accepted:"ac"}[s]):"";
  d.querySelector("td").innerHTML=`<div class="dgrid">
    <div class="dcard"><div class="h"><span class="ic">▸</span> ${esc(f.vtitle)} · ${esc(f.cwe)} · ${esc(f.owasp)}</div><div class="bd">
      <div class="remedy" style="margin-bottom:10px">${esc(f.evidence)||"—"}</div>
      ${f.payload?`<div class="kv"><span class="k">Payload</span><span class="v" style="color:var(--amber)">${esc(f.payload)}</span></div>`:""}
      <div class="kv"><span class="k">Detection</span><span class="v">${esc(f.detection||"—")} · ${esc(f.confidence||"—")}</span></div>
      ${f.repro?`<div class="kv"><span class="k">Repro</span></div><div class="code">${esc(f.repro)}</div>`:""}</div></div>
    <div class="dcard"><div class="h"><span class="ic">⇄</span> Request / Response proof</div><div class="bd">${exs}</div></div></div>
    <div class="dcard warn" style="margin:0 18px 14px"><div class="h"><span class="ic">✎</span> Remediation</div><div class="bd remedy">${esc(f.vfix)||"—"}</div></div>
    <div class="actions">
      <div class="abtn ok${on("confirmed")}" data-t="confirmed">✓ Confirm</div>
      <div class="abtn fp${on("false_positive")}" data-t="false_positive">⦸ False positive</div>
      <div class="abtn ac${on("accepted")}" data-t="accepted">◉ Accept risk</div>
      <div class="notebox"><input id="note${id}" placeholder="analyst note…" value="${esc(f.analyst_note||"")}"><div class="abtn" data-save="${id}">save</div></div>
      <div class="abtn" style="margin-left:auto" onclick="window.open('/api/report/${encodeURIComponent(SCAN)}','_blank')">↗ report</div></div>`;
  d.querySelectorAll(".abtn[data-t]").forEach(b=>b.onclick=()=>triage(id,b.dataset.t));
  d.querySelector(".abtn[data-save]").onclick=()=>saveNote(id);
}
async function triage(id,status){
  try{await api(`/api/findings/${id}/triage`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({status})});
    const f=FINDINGS.find(x=>x.id===id);if(f)f.triage_status=status;fbody();
    const d=document.getElementById("d"+id);if(d)d.style.display="none";toggleFinding(id);
    toast("marked "+status.replace("_"," "));}catch(e){toast("triage failed",1);}
}
async function saveNote(id){
  const v=document.getElementById("note"+id).value;
  try{await api(`/api/findings/${id}/note`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({note:v})});
    const f=FINDINGS.find(x=>x.id===id);if(f)f.analyst_note=v;toast("note saved");}catch(e){toast("note failed",1);}
}

// ---------- ATTACK SURFACE ----------
async function renderSurface(p){
  const fr=await api(`/api/scans/${encodeURIComponent(SCAN)}/frontier`);
  p.innerHTML=`<table class="tbl"><thead><tr><th>URL</th><th>Discovered by</th><th>Params</th><th>Target</th><th>Hit by finding</th></tr></thead>
    <tbody>${fr.map(u=>`<tr class="row"><td><span class="url" title="${esc(u.url)}">${esc(u.url)}</span></td>
      <td>${u.discovered_by?`<span class="srcbadge">${esc(u.discovered_by)}</span>`:'<span class="mut">—</span>'}</td>
      <td>${u.param_count||0}</td><td class="${u.is_target?"tgt-y":"tgt-n"}">${u.is_target?"yes":"—"}</td>
      <td class="${u.hit_by?"hit-y":"hit-n"}">${u.hit_by?esc(u.hit_by):"—"}</td></tr>`).join("")}</tbody></table>
    <div class="note"><b>What the scanner saw, not just what it flagged.</b> Full crawl reach, and which URLs a finding actually landed on (precise full-url match).</div>`;
}
// ---------- ENGINES ----------
async function renderEngines(p){
  const pr=await api(`/api/scans/${encodeURIComponent(SCAN)}/probes`);
  p.innerHTML=pr.map(e=>{
    const cls=e.ran?"st-ran":(e.expected?"st-miss":"st-skip");const lbl=e.ran?"ran":(e.expected?"MISSING":"skipped");
    return `<div class="enrow"><div class="en"><span class="dotg ${e.ran?"g":"m"}"></span>${esc(e.engine)}</div>
      <div class="st ${cls}">${lbl}</div><div class="nt" title="${esc(e.note||"")}">${esc(e.note||"—")}</div>
      <div class="fc">${e.findings_count!=null?e.findings_count:"—"}</div></div>`;
  }).join("")+`<div class="note"><b>What every engine did.</b> Ran vs expected, its note, and finding count. A zero-finding engine reads "ran clean"; an expected-but-missing engine shows red.</div>`;
}
// ---------- TIMELINE ----------
async function renderTimeline(p){
  const ev=await api(`/api/scans/${encodeURIComponent(SCAN)}/events`);
  if(!ev.length){p.innerHTML=`<div class="empty">no timeline events recorded for this scan<br><span style="color:var(--ink3)">older scans predate event capture; new scans stream stage/reauth/halt events here</span></div>`;return;}
  p.innerHTML=`<div class="tl">${ev.map(e=>{const w=/reauth|halt|session|lost|drop/i.test((e.kind||"")+(e.message||""));
    return `<div class="tlrow${w?" warn":""}"><span class="ts">${e.ts?("+"+e.ts+"s"):(e.seq)}</span><span class="ms">${esc(e.message||e.kind||"")}${e.stage?` <span class="sub">· ${esc(e.stage)}</span>`:""}</span></div>`;}).join("")}</div>`;
}
// ---------- EVIDENCE ----------
async function renderEvidence(p){
  const ex=await api(`/api/scans/${encodeURIComponent(SCAN)}/evidence?size=1000`);
  p.innerHTML=`<div class="toolbar"><div class="search"><input id="eq" placeholder="search ${ex.length} exchanges — url or label…"></div></div>
    <table class="tbl"><thead><tr><th>#</th><th>Tool</th><th>Label</th><th>Method</th><th>URL</th><th>Status</th></tr></thead>
    <tbody id="ebody"></tbody></table>`;
  const draw=q=>{const rows=ex.filter(e=>!q||((e.request.url||"")+(e.label||"")).toLowerCase().includes(q));
    document.getElementById("ebody").innerHTML=rows.map((e,i)=>`<tr class="row"><td class="mut">${String(i+1).padStart(3,"0")}</td>
      <td><span class="chiptool">${esc(e.tool||"")}</span></td><td>${esc(e.label||"")}</td><td>${esc(e.request.method||"")}</td>
      <td><span class="url" title="${esc(e.request.url)}">${esc(e.request.url||"")}</span></td>
      <td class="${e.response.status>=500?"sev-high":e.response.status>=400?"sev-medium":"mut"}">${e.response.status==null?"—":e.response.status}</td></tr>`).join("")||'<tr><td colspan="6"><div class="empty">no matches</div></td></tr>';};
  document.getElementById("eq").oninput=e=>draw(e.target.value.toLowerCase());draw("");
}
// ---------- RAW DATA ----------
const RCOLS=["kind","source","type","url","param","method","severity","status","detail"];
const RDROP=new Set(["kind","source","method","severity","status"]);
async function renderRaw(p){
  if(!RAW)RAW=await api(`/api/scans/${encodeURIComponent(SCAN)}/raw?size=5000`);
  p.innerHTML=`<div class="rawbar"><div class="search" style="max-width:340px"><input id="rawq" placeholder="search every collected record…"></div>
      <div class="clr" id="rawclr">clear filters</div><div class="cnt"><b id="rawn">0</b> of ${RAW.length} records</div></div>
    <table class="rtbl" id="rtbl"><thead>
      <tr><th data-s="kind" style="width:84px">Kind</th><th data-s="source" style="width:92px">Source</th>
        <th data-s="type" style="width:120px">Type</th><th data-s="url">URL / Target</th><th data-s="param" style="width:84px">Param</th>
        <th data-s="method" style="width:60px">Method</th><th data-s="severity" style="width:78px">Severity</th>
        <th data-s="status" style="width:92px">Status</th><th data-s="detail" style="width:220px">Detail</th></tr>
      <tr class="filt">${RCOLS.map(c=>RDROP.has(c)?`<th><select class="rf-select" data-c="${c}"></select></th>`:`<th><input class="rf-input" data-c="${c}" placeholder="filter…"></th>`).join("")}</tr>
    </thead><tbody id="rbody"></tbody></table>
    <div class="note"><b>Every collected record in one grid</b> — findings, URLs, engine runs, exchanges, events. Each column filters independently, stacked with the global search and sortable headers.</div>`;
  p.querySelectorAll(".rf-select").forEach(sel=>{const c=sel.dataset.c;const vals=[...new Set(RAW.map(r=>r[c]))].filter(v=>v&&v!=="").sort();
    sel.innerHTML='<option value="">all</option>'+vals.map(v=>`<option>${esc(v)}</option>`).join("");sel.value=rfilt[c]||"";sel.classList.toggle("on",!!rfilt[c]);
    sel.onchange=()=>{rfilt[c]=sel.value;sel.classList.toggle("on",!!sel.value);rbody();};});
  p.querySelectorAll(".rf-input").forEach(inp=>{inp.value=rfilt[inp.dataset.c]||"";inp.oninput=()=>{rfilt[inp.dataset.c]=inp.value.toLowerCase();rbody();};});
  document.getElementById("rawq").oninput=e=>{rQ=e.target.value.toLowerCase();rbody();};document.getElementById("rawq").value=rQ;
  p.querySelectorAll("#rtbl thead th[data-s]").forEach(th=>th.onclick=()=>{const k=th.dataset.s;if(rSort===k)rDir*=-1;else{rSort=k;rDir=1;}rbody();});
  document.getElementById("rawclr").onclick=()=>{rfilt={};rQ="";renderRaw(p);};
  rbody();
}
function rbody(){
  const body=document.getElementById("rbody");if(!body)return;
  let rows=RAW.filter(r=>RCOLS.every(c=>{const f=rfilt[c];if(!f)return true;return RDROP.has(c)?r[c]===f:String(r[c]||"").toLowerCase().includes(f);}))
    .filter(r=>!rQ||RCOLS.some(c=>String(r[c]||"").toLowerCase().includes(rQ)));
  if(rSort)rows=rows.slice().sort((a,b)=>{const x=String(a[rSort]||""),y=String(b[rSort]||"");return(x<y?-1:x>y?1:0)*rDir;});
  body.innerHTML=rows.slice(0,2000).map(r=>{const sv=r.severity&&SEV.includes(r.severity)?`<span class="sv-${r.severity}">${r.severity}</span>`:'<span class="m">—</span>';
    return `<tr><td><span class="kb kb-${r.kind}">${r.kind}</span></td><td class="${r.source?"":"m"}">${esc(r.source||"—")}</td>
      <td>${esc(r.type||"")}</td><td class="${r.url?"u":"m"}" title="${esc(r.url)}">${esc(r.url||"—")}</td>
      <td class="${r.param?"":"m"}">${esc(r.param||"—")}</td><td class="${r.method?"":"m"}">${esc(r.method||"—")}</td>
      <td>${sv}</td><td>${esc(r.status||"")}</td><td title="${esc(r.detail)}">${esc(r.detail||"")}</td></tr>`;}).join("")
    ||'<tr><td colspan="9"><div class="empty">no records match these filters</div></td></tr>';
  document.getElementById("rawn").textContent=rows.length;
}
// ---------- LIVE ----------
async function pollLive(){
  try{const l=await api(`/api/scans/${encodeURIComponent(SCAN)}/live`);
    const bar=document.getElementById("livebar");
    if(l&&l.status==="in-progress"){bar.innerHTML=`<div class="livebar"><span class="live"><span class="p"></span></span> live · stage ${esc(l.last_stage||"?")} · ${l.n_findings||0} findings · ${l.elapsed_s||0}s`+
      (l.urls?` · ${l.urls} urls`:"")+`</div>`;}
    else{bar.innerHTML="";clearInterval(livtimer);selectScan(SCAN);}
  }catch(e){}
}
document.getElementById("exportbtn").onclick=e=>{e.stopPropagation();document.getElementById("exportmenu").classList.toggle("on");};
document.addEventListener("click",e=>{if(!e.target.closest(".exportwrap"))document.getElementById("exportmenu").classList.remove("on");});
loadScans().then(()=>{document.getElementById("boot").style.display="none";}).catch(e=>{document.getElementById("boot").textContent="failed to load ("+e.message+")";});
setInterval(()=>{if(!fOpen)loadScans();},15000);
</script></body></html>"""
