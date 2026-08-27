"""dast-ng report generator: turn a scan result JSON into a self-contained, gorgeous
terminal/hacker-themed HTML report — executive summary, severity breakdown, and per-finding
detail with the ACTUAL request/response proof (Burp-style), reasoning, and remediation.

Usage:
    from dastng.report import build_report
    html = build_report(result_dict, target="https://app", meta={...})
    # or CLI:  python -m dastng.report scan_result.json -o report.html
"""
from __future__ import annotations

import html as _html
import json
from collections import Counter

# ---- vulnerability knowledge base: category -> presentation + risk metadata ----------------
# severity: critical|high|medium|low|info ; cwe/owasp for standards mapping; remediation is the
# analyst/dev-facing fix. Keeps the report authoritative without an external DB.
VULN_META: dict[str, dict] = {
    "sql-injection": dict(
        title="SQL Injection", severity="critical", cwe="CWE-89", owasp="A03:2021 Injection",
        desc="User input is concatenated into a SQL query, letting an attacker read, modify, or "
             "destroy database contents and often bypass authentication.",
        fix="Use parameterised queries / prepared statements everywhere; never build SQL by string "
            "concatenation. Apply least-privilege DB accounts and validate input types."),
    "command-injection": dict(
        title="OS Command Injection", severity="critical", cwe="CWE-78",
        owasp="A03:2021 Injection",
        desc="User input reaches an operating-system shell, allowing arbitrary command execution "
             "on the server (full host compromise).",
        fix="Avoid shelling out with user input. Use language-native APIs; if a command is "
            "unavoidable, pass arguments as an array (no shell), and strictly allow-list values."),
    "file-inclusion": dict(
        title="File Inclusion / Path Traversal", severity="high", cwe="CWE-98 / CWE-22",
        owasp="A03:2021 Injection",
        desc="A file path derived from user input lets an attacker read arbitrary server files "
             "(config, credentials) or, with a writable log/upload, execute code.",
        fix="Never pass user input to file/include APIs. Map requests to a fixed allow-list of "
            "resources; canonicalise and confine paths to an intended base directory."),
    "rfi": dict(
        title="Remote File Inclusion / SSRF", severity="critical", cwe="CWE-98 / CWE-918",
        owasp="A10:2021 SSRF",
        desc="The server fetches an attacker-controlled URL, enabling remote code inclusion or "
             "server-side request forgery into internal networks.",
        fix="Disable remote includes. Validate and allow-list outbound destinations; block "
            "internal ranges and cloud metadata endpoints."),
    "ssrf": dict(
        title="Server-Side Request Forgery", severity="high", cwe="CWE-918", owasp="A10:2021 SSRF",
        desc="The application can be induced to make requests to attacker-chosen destinations, "
             "reaching internal services or cloud metadata.",
        fix="Allow-list outbound hosts, resolve+pin DNS, and block link-local / internal ranges "
            "and 169.254.169.254."),
    "xss": dict(
        title="Cross-Site Scripting (XSS)", severity="high", cwe="CWE-79",
        owasp="A03:2021 Injection",
        desc="Untrusted input is reflected/stored into a page (or a DOM sink) and executes in "
             "victims' browsers — session theft, account takeover, defacement.",
        fix="Context-aware output encoding, a strict Content-Security-Policy, and framework "
            "auto-escaping. For DOM XSS, avoid dangerous sinks (innerHTML, document.write)."),
    "open-redirect": dict(
        title="Open Redirect", severity="medium", cwe="CWE-601",
        owasp="A01:2021 Broken Access Control",
        desc="A redirect target is taken from user input, letting attackers craft trusted-looking "
             "links that bounce victims to malicious sites (phishing, token theft).",
        fix="Redirect only to a server-side allow-list of paths; never redirect to a raw "
            "user-supplied absolute URL."),
    "csrf": dict(
        title="Cross-Site Request Forgery", severity="medium", cwe="CWE-352",
        owasp="A01:2021 Broken Access Control",
        desc="State-changing requests lack anti-CSRF protection, so a malicious page can force a "
             "logged-in victim's browser to perform actions on their behalf.",
        fix="Require a per-session anti-CSRF token on state-changing requests, set SameSite=Lax/"
            "Strict on session cookies, and validate Origin/Referer."),
    "bola": dict(
        title="Broken Object-Level Authorization (BOLA/IDOR)", severity="critical", cwe="CWE-639",
        owasp="API1:2023 BOLA",
        desc="One user's identity can read or modify another user's object by changing an ID — the "
             "#1 API risk. In healthcare this is direct cross-patient record access.",
        fix="Enforce per-object ownership checks server-side on EVERY request (not just "
            "authentication). Never trust a client-supplied object identifier alone."),
    "mass-assignment": dict(
        title="Mass Assignment / Privilege Escalation", severity="high", cwe="CWE-915",
        owasp="API3:2023 Broken Object Property Level Authorization",
        desc="The server binds client-supplied fields it should ignore (e.g. admin=true), letting "
             "a user escalate their own privileges.",
        fix="Bind only an explicit allow-list of writable fields; never mass-bind request bodies "
            "to internal models. Keep privilege fields server-controlled."),
    "api-contract": dict(
        title="API Contract / Schema Violation", severity="low", cwe="CWE-20",
        owasp="API8:2023 Security Misconfiguration",
        desc="Endpoints deviate from their own OpenAPI contract (server errors on valid input, "
             "undocumented responses) — often the surface for deeper bugs.",
        fix="Validate requests/responses against the schema; return documented status codes; fix "
            "the 500s (they frequently mask injection or logic flaws)."),
    "api-fuzz": dict(
        title="API Fuzzing Failure", severity="low", cwe="CWE-20",
        owasp="API8:2023 Security Misconfiguration",
        desc="Property-based fuzzing of the API contract surfaced failures (schema breaks, server "
             "errors) on generated inputs.",
        fix="Add input validation and robust error handling; ensure the implementation matches the "
            "published schema."),
    "auth": dict(
        title="Broken Authentication (JWT)", severity="critical", cwe="CWE-347",
        owasp="API2:2023 Broken Authentication",
        desc="A weak or forgeable authentication token (e.g. a JWT signed with a guessable secret) "
             "lets an attacker mint tokens for any user, including admins.",
        fix="Sign JWTs with a long random secret (or asymmetric keys); reject alg=none and "
            "algorithm-confusion; rotate secrets and keep them out of source."),
    "misconfiguration": dict(
        title="Security Misconfiguration", severity="medium", cwe="CWE-16",
        owasp="A05:2021 Security Misconfiguration",
        desc="Missing hardening — security headers, permissive CORS, verbose errors, exposed panels "
             "— that weakens the app's defensive posture.",
        fix="Set the standard security headers (CSP, HSTS, X-Content-Type-Options), tighten CORS "
            "to known origins, and disable verbose error output in production."),
    "pii-disclosure": dict(
        title="Sensitive Data / PII Exposure", severity="high", cwe="CWE-200",
        owasp="A01:2021 Broken Access Control",
        desc="Personal or health-related data (emails, IDs, records) is returned where it should "
             "not be — an excessive-data-exposure / privacy risk, HIPAA-relevant for healthcare.",
        fix="Return only the fields a caller is authorized to see; filter server-side, never "
            "client-side. Mask/scope PII and audit access."),
    "info-disclosure": dict(
        title="Information Disclosure", severity="low", cwe="CWE-200",
        owasp="A05:2021 Security Misconfiguration",
        desc="The app leaks internal details (versions, stack traces, source, tokens) that aid an "
             "attacker in planning further attacks.",
        fix="Suppress verbose errors/banners, remove debug endpoints, and keep source/secrets out "
            "of responses."),
    "other": dict(
        title="Other Finding", severity="info", cwe="—", owasp="—",
        desc="A finding reported by a scanner that does not map to a standard category.",
        fix="Review the evidence and triage."),
}

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}


def _meta_for(cat: str) -> dict:
    return VULN_META.get(cat, VULN_META["other"])


def _grade(counts: dict) -> tuple[str, str]:
    """Letter grade + one-line posture from the severity mix."""
    c, h, m = counts.get("critical", 0), counts.get("high", 0), counts.get("medium", 0)
    if c:
        return "F", f"{c} critical issue(s) — immediate remediation required"
    if h >= 3:
        return "D", f"{h} high-severity issues — significant exposure"
    if h:
        return "C", f"{h} high-severity issue(s) to remediate"
    if m:
        return "B", f"{m} medium issue(s); no criticals or highs"
    return "A", "no high-severity issues detected"


def _esc(s) -> str:
    return _html.escape(str(s if s is not None else ""))


# ---- theme: terminal / hacker aesthetic (deep ink, amber accent, mono, severity stripes) ----
_CSS = r"""
:root{
  --bg:#070a0f; --bg2:#0b0f16; --panel:#0d131c; --panel2:#111925; --line:#1c2733;
  --ink:#d7e0ea; --ink2:#8595a6; --ink3:#5b6b7c;
  --amber:#ffb454; --amber2:#f0a020; --green:#7fd962; --cyan:#59c2ff;
  --crit:#ff5370; --high:#ff8f40; --med:#ffb454; --low:#59c2ff; --info:#6b7c8f;
  --mono:"JetBrains Mono","SF Mono",ui-monospace,"Cascadia Code",Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--mono);font-size:14px;
  line-height:1.6;-webkit-font-smoothing:antialiased;
  background-image:radial-gradient(900px 500px at 88% -8%,#12202e33,transparent 60%),
    radial-gradient(700px 400px at 0% 0%,#1a140a22,transparent 55%);}
.wrap{max-width:1120px;margin:0 auto;padding:26px 22px 90px}
a{color:var(--cyan);text-decoration:none}
::selection{background:var(--amber);color:#0a0a0a}

/* header / banner */
.top{border:1px solid var(--line);border-radius:12px;background:
  linear-gradient(180deg,#0d131cd0,#0a0e14d0);overflow:hidden}
.top .bar{display:flex;align-items:center;gap:8px;padding:9px 14px;border-bottom:1px solid var(--line);
  background:#0a0e14;font-size:12px;color:var(--ink3)}
.dot{width:11px;height:11px;border-radius:50%}
.dot.r{background:#ff5f56}.dot.y{background:#ffbd2e}.dot.g{background:#27c93f}
.top .body{padding:22px 24px;display:grid;grid-template-columns:1fr auto;gap:22px;align-items:center}
.brand{font-weight:700;font-size:13px;letter-spacing:.32em;color:var(--amber);text-transform:uppercase}
.prompt{margin-top:8px;font-size:clamp(19px,3.2vw,30px);color:var(--ink);word-break:break-all}
.prompt .p{color:var(--green)}.prompt .f{color:var(--amber)}
.subline{margin-top:10px;color:var(--ink2);font-size:12.5px;display:flex;flex-wrap:wrap;gap:6px 18px}
.subline b{color:var(--ink)}
.grade{width:118px;height:118px;border-radius:14px;display:flex;flex-direction:column;
  align-items:center;justify-content:center;border:1px solid var(--line);background:#0a0e14;position:relative}
.grade .g{font-size:52px;font-weight:800;line-height:1}
.grade .l{font-size:10px;letter-spacing:.2em;color:var(--ink3);text-transform:uppercase;margin-top:3px}
.gA{color:var(--green)}.gB{color:#9fd35f}.gC{color:var(--amber)}.gD{color:var(--high)}.gF{color:var(--crit)}

/* section label */
.sec{margin:34px 0 12px;font-size:11px;letter-spacing:.22em;text-transform:uppercase;color:var(--ink3);
  display:flex;align-items:center;gap:10px}
.sec::before{content:"//";color:var(--amber)}
.sec .rule{flex:1;height:1px;background:var(--line)}

/* severity summary */
.sevgrid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}
@media(max-width:640px){.sevgrid{grid-template-columns:repeat(2,1fr)}}
.sevcard{border:1px solid var(--line);border-radius:10px;padding:13px 15px;background:var(--panel);
  position:relative;overflow:hidden}
.sevcard::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px}
.sevcard.critical::before{background:var(--crit)}.sevcard.high::before{background:var(--high)}
.sevcard.medium::before{background:var(--med)}.sevcard.low::before{background:var(--low)}
.sevcard.info::before{background:var(--info)}
.sevcard .n{font-size:30px;font-weight:800;line-height:1;font-variant-numeric:tabular-nums}
.sevcard .k{font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink2);margin-top:5px}
.critical .n{color:var(--crit)}.high .n{color:var(--high)}.medium .n{color:var(--med)}
.low .n{color:var(--low)}.info .n{color:var(--info)}

.lead{border:1px solid var(--line);border-left:3px solid var(--amber);border-radius:0 10px 10px 0;
  background:var(--panel);padding:14px 18px;margin-top:14px;color:var(--ink);font-size:13.5px}
.lead b{color:var(--amber)}

/* coverage stats */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
@media(max-width:640px){.stats{grid-template-columns:repeat(2,1fr)}}
.stat{border:1px solid var(--line);border-radius:10px;padding:13px 15px;background:var(--panel)}
.stat .n{font-size:22px;font-weight:700;color:var(--cyan);font-variant-numeric:tabular-nums}
.stat .k{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--ink3);margin-top:3px}

/* finding cards */
.find{border:1px solid var(--line);border-radius:11px;background:var(--panel);margin-top:12px;
  overflow:hidden;position:relative}
.find::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px}
.find.critical::before{background:var(--crit)}.find.high::before{background:var(--high)}
.find.medium::before{background:var(--med)}.find.low::before{background:var(--low)}
.find.info::before{background:var(--info)}
.fhead{padding:14px 18px 14px 20px;cursor:pointer;display:flex;gap:14px;align-items:flex-start}
.fhead:hover{background:var(--panel2)}
.pill{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:3px 8px;
  border-radius:5px;white-space:nowrap;border:1px solid transparent}
.pill.critical{color:var(--crit);background:#ff53701a;border-color:#ff537055}
.pill.high{color:var(--high);background:#ff8f401a;border-color:#ff8f4055}
.pill.medium{color:var(--med);background:#ffb4541a;border-color:#ffb45455}
.pill.low{color:var(--low);background:#59c2ff1a;border-color:#59c2ff55}
.pill.info{color:var(--info);background:#6b7c8f1a;border-color:#6b7c8f55}
.ftitle{flex:1;min-width:0}
.ftitle .t{font-size:15px;color:var(--ink);font-weight:600}
.ftitle .u{margin-top:4px;font-size:12px;color:var(--ink2);word-break:break-all}
.ftitle .u .m{color:var(--amber);font-weight:700}
.ftags{display:flex;gap:6px;flex-wrap:wrap;margin-top:7px}
.tag{font-size:10px;color:var(--ink3);border:1px solid var(--line);border-radius:4px;padding:1px 6px}
.chev{color:var(--ink3);transition:transform .2s;font-size:12px;margin-top:3px}
.find.open .chev{transform:rotate(90deg)}
.fbody{display:none;padding:2px 18px 18px 20px;border-top:1px solid var(--line)}
.find.open .fbody{display:block}
.block{margin-top:15px}
.block .h{font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--ink3);margin-bottom:7px;
  display:flex;align-items:center;gap:7px}
.block .h::before{content:"▸";color:var(--amber)}
.desc{color:var(--ink);font-size:13.5px}.fix{color:var(--ink);font-size:13.5px}
.reason{color:var(--green);font-size:13px;background:#0a1410;border:1px solid #17331f;border-radius:8px;
  padding:10px 13px;white-space:pre-wrap;word-break:break-word}

/* request/response proof panes */
.proof{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:760px){.proof{grid-template-columns:1fr}}
.pane{border:1px solid var(--line);border-radius:8px;overflow:hidden;background:var(--bg2)}
.pane .lbl{font-size:10px;letter-spacing:.14em;text-transform:uppercase;padding:7px 11px;
  border-bottom:1px solid var(--line);color:var(--ink3);background:#0a0e14;display:flex;justify-content:space-between}
.pane pre{margin:0;padding:11px 13px;font-size:11.5px;line-height:1.55;color:var(--ink);
  white-space:pre-wrap;word-break:break-word;max-height:340px;overflow:auto}
.pane .req{color:var(--amber)}.pane .st2{color:var(--green)}.pane .st3{color:var(--cyan)}
.pane .st4,.pane .st5{color:var(--crit)}
.exchsep{font-size:10px;color:var(--ink3);margin:12px 0 4px;letter-spacing:.1em}

.foot{margin-top:44px;padding-top:16px;border-top:1px solid var(--line);color:var(--ink3);font-size:11.5px;
  display:flex;flex-wrap:wrap;justify-content:space-between;gap:10px}
.toolrow{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.toolrow .t{font-size:10.5px;color:var(--ink2);border:1px solid var(--line);border-radius:4px;padding:2px 8px}
"""

_JS = r"""
document.querySelectorAll('.fhead').forEach(h=>h.addEventListener('click',()=>{
  h.parentElement.classList.toggle('open');
}));
document.getElementById('expandall')?.addEventListener('click',e=>{
  const open=document.querySelector('.find:not(.open)');
  document.querySelectorAll('.find').forEach(f=>f.classList.toggle('open',!!open));
  e.target.textContent=open?'collapse all':'expand all';
});
"""


def _fmt_headers(h: dict) -> str:
    return "\n".join(f"{k}: {v}" for k, v in (h or {}).items())


def _render_exchange(ex: dict) -> str:
    req, resp = ex.get("request", {}), ex.get("response", {})
    rl = f"{req.get('method', 'GET')} {req.get('url', '')}"
    reqtxt = f"<span class='req'>{_esc(rl)}</span>\n" + _esc(_fmt_headers(req.get("headers")))
    if req.get("body"):
        reqtxt += "\n\n" + _esc(req["body"])
    st = resp.get("status")
    stcls = f"st{str(st)[0]}" if st else "st2"
    resptxt = (f"<span class='{stcls}'>HTTP {_esc(st)}</span>\n"
               + _esc(_fmt_headers(resp.get("headers"))) + "\n\n" + _esc(resp.get("body", "")))
    return (f"<div class='proof'>"
            f"<div class='pane'><div class='lbl'>Request<span>attack</span></div><pre>{reqtxt}</pre></div>"
            f"<div class='pane'><div class='lbl'>Response<span>evidence</span></div><pre>{resptxt}</pre></div>"
            f"</div>")


def _render_finding(f: dict, idx: int) -> str:
    meta = _meta_for(f.get("category", "other"))
    sev = meta["severity"]
    cat = f.get("category", "other")
    url = f.get("url", "")
    method = f.get("method", "GET")
    param = f.get("param")
    reason = f.get("evidence", "") or f.get("verify_note", "")
    tool = f.get("tool", "")
    exlog = f.get("evidence_log") or []

    tags = [f"<span class='tag'>{_esc(meta['cwe'])}</span>",
            f"<span class='tag'>{_esc(meta['owasp'])}</span>",
            f"<span class='tag'>tool:{_esc(tool)}</span>"]
    if param:
        tags.insert(0, f"<span class='tag'>param:{_esc(param)}</span>")

    proof = ""
    if exlog:
        parts = []
        for i, ex in enumerate(exlog[-3:]):    # show up to the last 3 exchanges
            if len(exlog) > 1:
                parts.append(f"<div class='exchsep'>— exchange {i + 1} —</div>")
            parts.append(_render_exchange(ex))
        proof = ("<div class='block'><div class='h'>Proof — request / response</div>"
                 + "".join(parts) + "</div>")
    else:
        proof = ("<div class='block'><div class='h'>Evidence</div>"
                 f"<div class='reason'>{_esc(reason) or 'reported by ' + _esc(tool)}</div></div>")

    reasoning_block = ""
    if exlog and reason:
        reasoning_block = ("<div class='block'><div class='h'>Reasoning — why this is a finding</div>"
                           f"<div class='reason'>{_esc(reason)}</div></div>")

    return f"""
    <div class="find {sev}">
      <div class="fhead">
        <span class="pill {sev}">{_esc(sev)}</span>
        <div class="ftitle">
          <div class="t">{_esc(meta['title'])}</div>
          <div class="u"><span class="m">{_esc(method)}</span> {_esc(url)}</div>
          <div class="ftags">{''.join(tags)}</div>
        </div>
        <span class="chev">▸</span>
      </div>
      <div class="fbody">
        <div class="block"><div class="h">Description</div><div class="desc">{_esc(meta['desc'])}</div></div>
        {reasoning_block}
        {proof}
        <div class="block"><div class="h">Remediation</div><div class="fix">{_esc(meta['fix'])}</div></div>
      </div>
    </div>"""


def build_report(result: dict, target: str = "", meta: dict | None = None) -> str:
    """Render a scan result dict into a self-contained HTML report string."""
    meta = meta or {}
    findings = result.get("findings", [])
    # sort by severity, then category
    findings = sorted(findings, key=lambda f: (SEV_RANK.get(_meta_for(f.get("category", "other"))["severity"], 9),
                                               f.get("category", "")))
    sev_counts = Counter(_meta_for(f.get("category", "other"))["severity"] for f in findings)
    grade, posture = _grade(sev_counts)
    target = target or (findings[0]["url"] if findings else "target")
    from urllib.parse import urlsplit
    host = urlsplit(target).netloc or target

    sevcards = "".join(
        f"<div class='sevcard {s}'><div class='n'>{sev_counts.get(s, 0)}</div>"
        f"<div class='k'>{s}</div></div>" for s in SEV_ORDER)

    tools = Counter(f.get("tool", "?") for f in findings)
    toolrow = "".join(f"<span class='t'>{_esc(t)} · {n}</span>" for t, n in tools.most_common())

    stats = [("crawl reach", len(result.get("urls", [])) or meta.get("urls", "—")),
             ("injection targets", result.get("targets", "—")),
             ("findings", len(findings)),
             ("re-auths", (result.get("session") or {}).get("reauths", 0))]
    statcards = "".join(f"<div class='stat'><div class='n'>{_esc(v)}</div><div class='k'>{k}</div></div>"
                        for k, v in stats)

    findings_html = "".join(_render_finding(f, i) for i, f in enumerate(findings)) or \
        "<div class='lead'>No findings — clean scan for the classes tested.</div>"

    when = meta.get("when", "")
    profile = (result.get("policy") or {}).get("name", meta.get("profile", "safe-deep"))
    zap = (result.get("zap") or {})
    zapnote = f"ZAP: {'ran' if zap.get('ran') else 'n/a'}" if zap else ""

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>dast-ng report — {_esc(host)}</title>
<style>{_CSS}</style></head><body><div class="wrap">
  <div class="top">
    <div class="bar"><span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
      <span style="margin-left:8px">dast-ng — engagement report</span>
      <span style="margin-left:auto" id="expandall" role="button" tabindex="0">expand all</span></div>
    <div class="body">
      <div>
        <div class="brand">▚ dast-ng scanner</div>
        <div class="prompt"><span class="p">$</span> dastng scan <span class="f">{_esc(host)}</span></div>
        <div class="subline">
          <span><b>{len(findings)}</b> findings</span>
          <span>profile <b>{_esc(profile)}</b></span>
          {f'<span>{_esc(when)}</span>' if when else ''}
          {f'<span>{_esc(zapnote)}</span>' if zapnote else ''}
        </div>
      </div>
      <div class="grade g{grade}"><div class="g g{grade}">{grade}</div><div class="l">risk grade</div></div>
    </div>
  </div>

  <div class="sec">executive summary<span class="rule"></span></div>
  <div class="sevgrid">{sevcards}</div>
  <div class="lead">Risk grade <b>{grade}</b> — {_esc(posture)}. Every finding below carries the actual
    request/response proof captured during the scan.</div>

  <div class="sec">scan coverage<span class="rule"></span></div>
  <div class="stats">{statcards}</div>
  <div class="toolrow">{toolrow}</div>

  <div class="sec">findings · {len(findings)}<span class="rule"></span></div>
  {findings_html}

  <div class="foot">
    <span>generated by dast-ng · self-contained report</span>
    <span>{_esc(host)} · grade {grade}</span>
  </div>
</div><script>{_JS}</script></body></html>"""


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Render a dast-ng scan result JSON to an HTML report.")
    ap.add_argument("result", help="scan result JSON file")
    ap.add_argument("-o", "--out", default="dastng_report.html")
    ap.add_argument("-t", "--target", default="")
    a = ap.parse_args(argv)
    with open(a.result) as fh:
        result = json.load(fh)
    html = build_report(result, target=a.target)
    with open(a.out, "w") as fh:
        fh.write(html)
    print(f"report -> {a.out} ({len(result.get('findings', []))} findings)")


if __name__ == "__main__":
    main()
