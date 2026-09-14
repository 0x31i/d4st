"""d4st engagement report — self-contained, client-grade HTML deliverable.

Light, print/PDF-ready (Cmd-P → Save as PDF), zero dependencies. Replaces a commercial
DAST report. NO grade — severity distribution + plain-language posture, never a scorecard.

Core principle: MAXIMUM DETAIL. Every field the pipeline collected for a finding is
displayed — instance reasoning, payload, detection + confidence, verification verdict, the
FULL request/response attack sequence, raw tool output, repro curl, CWE/CAPEC/OWASP
classifications, authoritative references, remediation, and the URL it landed on. Nothing
collected is summarized away.

    d4st report scan.json -o report.html \
        --client "Example Corp" --ref ACME-2026-01 --prepared-by "Your Security Team"

See docs/report-plan.md.
"""
from __future__ import annotations

import html as _html
from collections import Counter, OrderedDict

# ---- vulnerability knowledge base (category -> title/severity/cwe/owasp/desc/fix) ----
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
    "broken-auth": dict(
        title="Broken Authentication (Missing Authorization Check)", severity="critical",
        cwe="CWE-306", owasp="A01:2021 Broken Access Control / API2:2023",
        desc="An authenticated API endpoint returns real data when the bearer token is removed "
             "entirely — the server does not enforce authentication on that route. Anyone on the "
             "network can read the data unauthenticated; in healthcare this is direct PHI exposure.",
        fix="Enforce authentication server-side on EVERY non-public route (deny-by-default). Do not "
            "rely on the SPA to attach a token — the API must reject requests that lack a valid one."),
    "broken-token-validation": dict(
        title="Broken Token Validation", severity="high", cwe="CWE-347",
        owasp="A01:2021 Broken Access Control / API2:2023 Broken Authentication",
        desc="An endpoint accepts a structurally-valid but bogus/unsigned JWT and returns data — the "
             "server is not verifying the token's signature or expiry, so an attacker can forge a "
             "token and act as any user.",
        fix="Verify the JWT signature against the trusted key and reject expired tokens and "
            "alg=none/algorithm-confusion on every request before serving data."),
    "idor-suspect": dict(
        title="IDOR Suspect (Object-Level Authorization)", severity="high", cwe="CWE-639",
        owasp="API1:2023 BOLA",
        desc="Changing an object identifier in the request returned a different valid object. This "
             "may indicate broken object-level authorization (cross-tenant/cross-patient data "
             "access) and MUST be confirmed manually with a second account before reporting.",
        fix="Enforce per-object ownership checks server-side on every request; never authorize on "
            "authentication alone. Confirm whether the returned object belongs to another tenant."),
    "secret-disclosure": dict(
        title="Hardcoded Secret / Credential Disclosure", severity="high", cwe="CWE-798",
        owasp="A07:2021 Identification and Authentication Failures",
        desc="A secret — database connection string, API key, access token, or private key — is "
             "hardcoded in client-delivered JavaScript, where any user can read it. A live DB "
             "connection string or cloud key is often directly abusable.",
        fix="Remove secrets from client code; keep them server-side. Rotate any exposed credential "
            "immediately, scope keys to least privilege, and add secret-scanning to CI."),
    "vulnerable-js-dependency": dict(
        title="Vulnerable JavaScript Dependency", severity="medium", cwe="CWE-1104 / CWE-937",
        owasp="A06:2021 Vulnerable and Outdated Components",
        desc="The app ships a JavaScript library with a version that has known published "
             "vulnerabilities (XSS, prototype pollution, ReDoS), reachable in the client.",
        fix="Upgrade the library to a patched release; track dependencies with SCA (retire.js / "
            "npm audit) and pin/patch known-vulnerable versions."),
    "tls-configuration": dict(
        title="TLS / Certificate Configuration", severity="medium", cwe="CWE-295 / CWE-326",
        owasp="A02:2021 Cryptographic Failures",
        desc="A TLS or certificate hygiene issue — an expired/invalid certificate or a deprecated "
             "protocol (TLS 1.0/1.1) still enabled — weakens transport security and fails modern "
             "compliance (PCI, HIPAA transmission security).",
        fix="Keep certificates valid and auto-renewed; disable TLS 1.0/1.1 and weak ciphers; require "
            "TLS 1.2+ with a strong cipher suite and HSTS."),
    # --- JWT attack suite (token integrity) ---
    "jwt-alg-none": dict(
        title="JWT Signature Bypass — alg:none Accepted", severity="critical", cwe="CWE-347",
        owasp="A02:2021 Cryptographic Failures / API2:2023 Broken Authentication",
        desc="The server accepted a token whose header declares no signature (alg:none) and returned "
             "authenticated data. An attacker can forge a token for ANY user or role — complete "
             "authentication bypass.",
        fix="Reject alg=none and any algorithm not on an explicit allow-list; verify the signature "
            "against the trusted key on every request before serving data."),
    "jwt-signature-strip": dict(
        title="JWT Signature Not Required", severity="critical", cwe="CWE-347",
        owasp="A02:2021 Cryptographic Failures / API2:2023",
        desc="The server accepted a token with its signature stripped or removed entirely — token "
             "integrity is not enforced, so any token can be forged.",
        fix="Require and verify a valid signature on every token; reject 2-segment/empty-signature tokens."),
    "jwt-signature-not-verified": dict(
        title="JWT Signature Not Verified", severity="critical", cwe="CWE-347",
        owasp="A02:2021 Cryptographic Failures / API2:2023",
        desc="A token with a valid structure but a corrupted signature was accepted — the server does "
             "not verify the signature, so forged tokens are trusted.",
        fix="Verify the JWT signature against the trusted key and reject any token that fails."),
    "jwt-weak-secret": dict(
        title="JWT Signed with a Weak/Default Secret", severity="critical", cwe="CWE-521 / CWE-347",
        owasp="A02:2021 Cryptographic Failures / A07:2021",
        desc="The HMAC signing secret is a weak/default value recovered offline. With the secret an "
             "attacker mints validly-signed tokens for any user or role — full authentication bypass "
             "and privilege escalation.",
        fix="Rotate to a long, random, high-entropy signing secret stored in a secret manager; "
            "consider asymmetric (RS256/ES256) signing so the signing key never reaches clients."),
    "jwt-kid-injection": dict(
        title="JWT kid Header Injection", severity="high", cwe="CWE-91 / CWE-347",
        owasp="A03:2021 Injection / API2:2023",
        desc="The token's kid (key id) header is attacker-influenceable (path traversal / SQLi), which "
             "can coerce the server into signing/verifying with an attacker-chosen key.",
        fix="Treat kid as untrusted input: validate against an allow-list of key ids; never use it in "
            "a file path or SQL query."),
    "jwt-key-header": dict(
        title="JWT Embeds a Key Reference (jku/x5u/jwk)", severity="medium", cwe="CWE-347",
        owasp="A02:2021 Cryptographic Failures",
        desc="The token header carries a key-reference parameter (jku/x5u/x5c/jwk). If the server "
             "fetches or trusts it, an attacker can supply their own key (key confusion / SSRF).",
        fix="Ignore embedded key references; verify only against pre-configured trusted keys."),
    # --- CORS ---
    "cors-credentialed-reflection": dict(
        title="Exploitable CORS — Reflected Origin with Credentials", severity="high",
        cwe="CWE-942", owasp="A05:2021 Security Misconfiguration",
        desc="The server reflects an arbitrary Origin AND allows credentials, so any attacker-"
             "controlled website can make authenticated cross-origin requests and read the victim's "
             "responses — a genuinely exploitable misconfiguration, not a benign header.",
        fix="Never reflect the Origin with Access-Control-Allow-Credentials:true. Allow only an "
            "explicit trusted-origin allow-list; disallow credentials for wildcarded responses."),
    "cors-origin-reflection": dict(
        title="CORS Reflects Arbitrary Origin", severity="medium", cwe="CWE-942",
        owasp="A05:2021 Security Misconfiguration",
        desc="The server reflects an arbitrary request Origin without credentials — cross-origin reads "
             "of non-credentialed responses are possible.",
        fix="Restrict Access-Control-Allow-Origin to an explicit trusted allow-list."),
    "cors-null-origin": dict(
        title="CORS Allows the 'null' Origin", severity="medium", cwe="CWE-942",
        owasp="A05:2021 Security Misconfiguration",
        desc="The server allows the 'null' Origin (sandboxed iframes, redirects, local files), which "
             "attacker contexts can present to make cross-origin reads.",
        fix="Never allow-list the 'null' origin; use an explicit trusted-origin allow-list."),
    # --- verb/method BFLA ---
    "broken-access-control": dict(
        title="Broken Access Control (Verb/Method Tampering)", severity="high", cwe="CWE-285 / CWE-650",
        owasp="A01:2021 Broken Access Control / API5:2023 BFLA",
        desc="Authorization is enforced inconsistently across HTTP methods — an endpoint rejects one "
             "method unauthenticated but accepts another (HEAD/case-variant/alternate verb), allowing "
             "the access control to be bypassed by changing the method.",
        fix="Apply authorization uniformly to ALL methods (deny-by-default); do not gate on an exact "
            "verb string. Return 405 for unsupported methods and 401/403 consistently."),
    "broken-object-level-authorization": dict(
        title="Broken Object-Level Authorization (Cross-Account BOLA/IDOR)", severity="critical",
        cwe="CWE-639", owasp="API1:2023 BOLA / A01:2021",
        desc="A second authenticated account retrieved the first account's object at the same endpoint "
             "— one user can read another user's data. Confirmed with two accounts (not a suspicion). "
             "In healthcare this is direct cross-patient PHI access.",
        fix="Enforce per-object ownership checks server-side on every request; authorize on the "
            "resource owner, never on authentication alone."),
    # --- websocket / realtime ---
    "host-header-injection": dict(
        title="Host Header Injection", severity="medium", cwe="CWE-644 / CWE-20",
        owasp="A03:2021 Injection / A05:2021 Security Misconfiguration",
        desc="A poisoned Host / X-Forwarded-Host request header is reflected in a redirect, cookie, or "
             "response body. Depending on how the app uses the host value this enables password-reset-"
             "link poisoning, web-cache poisoning, or routing-based SSRF.",
        fix="Never build absolute URLs or reset links from the request Host header; use a configured "
            "canonical hostname and validate Host against an allow-list at the edge."),
    "websocket-hub-exposed": dict(
        title="Realtime/WebSocket Hub Exposed", severity="info", cwe="CWE-16",
        owasp="A05:2021 Security Misconfiguration",
        desc="A SignalR/WebSocket hub is reachable. Recorded for completeness; the live socket may "
             "warrant manual message-flow review.",
        fix="Ensure the realtime channel enforces the same authentication/authorization as the HTTP "
            "API and validates every inbound message."),
    "other": dict(
        title="Other Finding", severity="info", cwe="—", owasp="—",
        desc="A finding reported by a scanner that does not map to a standard category.",
        fix="Review the evidence and triage."),
}

# R1 — classifications (CWE/CAPEC chain) and authoritative references per category.
_CLASSES: dict[str, list] = {
    "sql-injection": ["CWE-89: SQL Injection", "CWE-564: SQL Injection: Hibernate",
                      "CWE-943: Improper Neutralization in Data Query Logic", "CAPEC-66: SQL Injection"],
    "command-injection": ["CWE-78: OS Command Injection", "CWE-77: Command Injection",
                          "CAPEC-88: OS Command Injection"],
    "file-inclusion": ["CWE-98: PHP Remote File Inclusion", "CWE-22: Path Traversal",
                       "CWE-73: External Control of File Name or Path", "CAPEC-126: Path Traversal"],
    "rfi": ["CWE-98: PHP Remote File Inclusion", "CWE-918: Server-Side Request Forgery",
            "CAPEC-664: SSRF"],
    "ssrf": ["CWE-918: Server-Side Request Forgery", "CAPEC-664: Server Side Request Forgery"],
    "xss": ["CWE-79: Cross-site Scripting", "CWE-80: Basic XSS", "CWE-116: Improper Encoding/Escaping",
            "CAPEC-591: Reflected XSS", "CAPEC-592: Stored XSS"],
    "open-redirect": ["CWE-601: URL Redirection to Untrusted Site", "CAPEC-194: Fake the Source of Data"],
    "csrf": ["CWE-352: Cross-Site Request Forgery", "CAPEC-62: Cross Site Request Forgery"],
    "bola": ["CWE-639: Authorization Bypass Through User-Controlled Key", "CWE-284: Improper Access Control",
             "CAPEC-180: Exploiting Incorrectly Configured Access Control"],
    "mass-assignment": ["CWE-915: Improperly Controlled Modification of Dynamically-Determined Attributes",
                        "CWE-269: Improper Privilege Management"],
    "api-contract": ["CWE-20: Improper Input Validation", "CWE-345: Insufficient Verification of Data"],
    "api-fuzz": ["CWE-20: Improper Input Validation"],
    "auth": ["CWE-347: Improper Verification of Cryptographic Signature", "CWE-287: Improper Authentication",
             "CAPEC-593: Session Hijacking"],
    "misconfiguration": ["CWE-16: Configuration", "CWE-693: Protection Mechanism Failure",
                         "CWE-1021: Improper Restriction of Rendered UI Layers"],
    "pii-disclosure": ["CWE-200: Exposure of Sensitive Information", "CWE-359: Exposure of Private Personal Information"],
    "info-disclosure": ["CWE-200: Exposure of Sensitive Information", "CWE-209: Generation of Error Message with Sensitive Information"],
    "other": [],
}
_REFS: dict[str, list] = {
    "sql-injection": [("OWASP: SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection"),
                      ("PortSwigger: SQL injection", "https://portswigger.net/web-security/sql-injection"),
                      ("OWASP Cheat Sheet: SQLi Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html")],
    "command-injection": [("OWASP: Command Injection", "https://owasp.org/www-community/attacks/Command_Injection"),
                          ("PortSwigger: OS command injection", "https://portswigger.net/web-security/os-command-injection")],
    "file-inclusion": [("OWASP: Path Traversal", "https://owasp.org/www-community/attacks/Path_Traversal"),
                       ("PortSwigger: File path traversal", "https://portswigger.net/web-security/file-path-traversal")],
    "rfi": [("OWASP: SSRF", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"),
            ("PortSwigger: SSRF", "https://portswigger.net/web-security/ssrf")],
    "ssrf": [("OWASP: SSRF", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"),
             ("PortSwigger: SSRF", "https://portswigger.net/web-security/ssrf"),
             ("OWASP Cheat Sheet: SSRF Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html")],
    "xss": [("OWASP: Cross Site Scripting", "https://owasp.org/www-community/attacks/xss/"),
            ("PortSwigger: Cross-site scripting", "https://portswigger.net/web-security/cross-site-scripting"),
            ("OWASP Cheat Sheet: XSS Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html")],
    "open-redirect": [("OWASP: Unvalidated Redirects", "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"),
                      ("PortSwigger: DOM-based open redirection", "https://portswigger.net/web-security/dom-based/open-redirection")],
    "csrf": [("OWASP: CSRF", "https://owasp.org/www-community/attacks/csrf"),
             ("OWASP Cheat Sheet: CSRF Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html")],
    "bola": [("OWASP API Top 10: BOLA", "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"),
             ("PortSwigger: IDOR", "https://portswigger.net/web-security/access-control/idor")],
    "mass-assignment": [("OWASP API Top 10: BOPLA", "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"),
                        ("OWASP Cheat Sheet: Mass Assignment", "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html")],
    "api-contract": [("OWASP API Top 10 (2023)", "https://owasp.org/API-Security/editions/2023/en/0x11-t10/")],
    "api-fuzz": [("OWASP API Top 10 (2023)", "https://owasp.org/API-Security/editions/2023/en/0x11-t10/")],
    "auth": [("OWASP API Top 10: Broken Authentication", "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"),
             ("PortSwigger: JWT attacks", "https://portswigger.net/web-security/jwt")],
    "misconfiguration": [("OWASP: Security Misconfiguration", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
                         ("OWASP Secure Headers Project", "https://owasp.org/www-project-secure-headers/")],
    "pii-disclosure": [("OWASP: Sensitive Data Exposure", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
                       ("HHS: HIPAA Security Rule", "https://www.hhs.gov/hipaa/for-professionals/security/index.html")],
    "info-disclosure": [("OWASP: Information exposure", "https://owasp.org/www-community/Improper_Error_Handling"),
                        ("PortSwigger: Information disclosure", "https://portswigger.net/web-security/information-disclosure")],
    "other": [],
}

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}


def _meta_for(cat: str) -> dict:
    base = VULN_META.get(cat, VULN_META["other"])
    return {**base, "classes": _CLASSES.get(cat, []), "refs": _REFS.get(cat, [])}


def _sev_donut(counts: dict, total: int) -> str:
    """conic-gradient stops for a findings donut proportioned by the severity mix.
    No grade/verdict — the ring just shows the shape of what was found."""
    colors = {"critical": "var(--crit)", "high": "var(--high)", "medium": "var(--med)",
              "low": "var(--low)", "info": "var(--info)"}
    if total <= 0:
        return "var(--line2) 0 360deg"
    stops, acc = [], 0.0
    for s in SEV_ORDER:
        n = counts.get(s, 0)
        if not n:
            continue
        start = acc / total * 360
        acc += n
        end = acc / total * 360
        stops.append(f"{colors[s]} {start:.2f}deg {end:.2f}deg")
    return ", ".join(stops) or "var(--line2) 0 360deg"


def _headline(counts: dict) -> str:
    """One neutral, factual summary line — a count breakdown, not a judgement."""
    parts = [f"{counts.get(s, 0)} {s}" for s in SEV_ORDER if counts.get(s, 0)]
    return ", ".join(parts) if parts else "no findings for the classes tested"


def _esc(s) -> str:
    return _html.escape(str(s if s is not None else ""))


# ---- theme: modern, editorial, print-first client deliverable ----
_CSS = r"""
:root{
  --ink:#15171e; --ink2:#565e6e; --ink3:#8b93a3; --ink4:#aab1bf;
  --paper:#ffffff; --wash:#f7f8fa; --wash2:#edeff3; --hair:#e5e8ee; --hair-soft:#eef1f5;
  --accent:#5b5bd6; --accent2:#8785f0; --accent-ink:#4340bd; --accent-wash:#eeeffe;
  --crit:#e5484d; --high:#ef6817; --med:#d99408; --low:#3e63dd; --info:#8b8d98;
  --crit-wash:#fdecec; --high-wash:#fcefe6; --med-wash:#faf3df; --low-wash:#ecf0fe; --info-wash:#f1f2f4;
  --code-bg:#0d1117; --code-ink:#c9d1d9; --code-line:#1c2230;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
  --mono:"SF Mono","JetBrains Mono",ui-monospace,"Cascadia Code",Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html,body{margin:0;background:var(--wash2);color:var(--ink);
  font-family:var(--sans);font-size:14px;line-height:1.65;-webkit-font-smoothing:antialiased;
  text-rendering:optimizeLegibility;font-feature-settings:"kern","liga","cv11"}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.report{max-width:900px;margin:0 auto;background:var(--paper);
  box-shadow:0 0 0 1px rgba(20,30,60,.05),0 20px 60px -24px rgba(20,30,60,.22)}
.pad{padding:56px 68px}
h1,h2,h3{color:var(--ink);font-weight:750;letter-spacing:-.021em;text-wrap:balance;margin:0}
h2{font-size:27px;line-height:1.12}
h3{font-size:17px;letter-spacing:-.015em;margin:30px 0 2px}
p{margin:0 0 12px}
.muted{color:var(--ink3)}
.mono{font-family:var(--mono)}

/* section eyebrow with running number */
.section{position:relative}
.eyebrow{display:flex;align-items:center;gap:12px;font-size:11px;letter-spacing:.16em;text-transform:uppercase;
  font-weight:700;color:var(--accent);margin-bottom:16px}
.eyebrow .num{font-variant-numeric:tabular-nums;color:var(--ink4);font-weight:800}
.eyebrow .rule{flex:1;height:1px;background:linear-gradient(90deg,var(--hair),transparent)}
.lead{font-size:17px;line-height:1.55;color:var(--ink2);margin:16px 0 30px;max-width:60ch;font-weight:420}
.lead b{color:var(--ink);font-weight:650}

/* ---- cover ---- */
.cover{position:relative;overflow:hidden;color:#e9ecf4;padding:76px 68px 60px;min-height:1000px;
  display:flex;flex-direction:column;
  background:
    radial-gradient(680px 420px at 82% 6%, #5b5bd63d, transparent 60%),
    radial-gradient(560px 380px at 8% 96%, #e5484d24, transparent 62%),
    linear-gradient(158deg,#111420 0%,#151a2b 46%,#10131f 100%)}
.cover::before{content:"";position:absolute;inset:0;opacity:.5;pointer-events:none;
  background-image:linear-gradient(rgba(255,255,255,.028) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.028) 1px,transparent 1px);
  background-size:34px 34px;mask-image:radial-gradient(circle at 60% 34%,#000,transparent 78%)}
.cover>*{position:relative}
.cover .brand{display:flex;align-items:center;gap:12px;font-weight:800;letter-spacing:.30em;text-transform:uppercase;font-size:12px;color:#aab4d6}
.cover .brand .logo{max-height:40px;max-width:160px}
.cover .brand .bd{width:8px;height:8px;border-radius:50%;background:var(--accent2);box-shadow:0 0 14px var(--accent2)}
.cover .spacer{flex:1}
.cover .kicker{font-size:12px;letter-spacing:.22em;text-transform:uppercase;color:var(--accent2);font-weight:700;margin-bottom:20px}
.cover h1{color:#fff;font-size:52px;line-height:1.04;font-weight:800;letter-spacing:-.03em;margin:0 0 20px;max-width:15em}
.cover .client{font-size:19px;color:#c3cbe4;font-weight:500;margin-bottom:44px}
.cover .sevstrip{display:flex;flex-wrap:wrap;gap:9px;margin-bottom:40px}
.sevchip{display:inline-flex;align-items:center;gap:8px;font-size:12.5px;font-weight:650;color:#e9ecf4;
  background:#ffffff0f;border:1px solid #ffffff1f;border-radius:999px;padding:6px 14px 6px 11px}
.sevchip .dot{width:9px;height:9px;border-radius:50%}
.sevchip .n{font-weight:800;font-variant-numeric:tabular-nums}
.sd-crit{background:var(--crit)}.sd-high{background:var(--high)}.sd-med{background:var(--med)}.sd-low{background:var(--low)}.sd-info{background:var(--info)}
.cover .meta{display:grid;grid-template-columns:auto 1fr;gap:0;max-width:600px;border-top:1px solid #ffffff1a}
.cover .meta .k,.cover .meta .v{padding:11px 0;border-bottom:1px solid #ffffff12;font-size:13.5px}
.cover .meta .k{color:#8b95bb;font-weight:600;padding-right:28px}
.cover .meta .v{color:#dfe4f2}
.cover .confid{margin-top:30px;font-size:11.5px;line-height:1.55;color:#98a1c2;max-width:600px;
  padding-left:14px;border-left:2px solid var(--accent)}
.cover .foot{margin-top:22px;font-size:11px;color:#727ba0}

/* ---- executive summary ---- */
.riskrow{display:grid;grid-template-columns:auto auto 1fr;gap:34px;align-items:center;
  padding:26px 30px;border:1px solid var(--hair);border-radius:16px;background:var(--wash);margin:6px 0 8px}
.bignum{text-align:center}
.bignum .n{font-size:52px;font-weight:800;letter-spacing:-.03em;line-height:1;color:var(--ink)}
.bignum.attn .n{color:var(--crit)}
.bignum .l{font-size:11px;letter-spacing:.05em;color:var(--ink3);margin-top:8px;text-transform:uppercase;font-weight:600}
.bignum .divider{width:1px;align-self:stretch;background:var(--hair)}
.riskbarwrap{min-width:0}
.riskbar{display:flex;height:26px;border-radius:8px;overflow:hidden;background:var(--wash2);box-shadow:inset 0 0 0 1px var(--hair)}
.riskbar .seg{display:flex;align-items:center;justify-content:center;color:#fff;font-size:11.5px;font-weight:800;min-width:26px}
.riskbar .seg.s-crit{background:var(--crit)}.riskbar .seg.s-high{background:var(--high)}
.riskbar .seg.s-med{background:var(--med)}.riskbar .seg.s-low{background:var(--low)}.riskbar .seg.s-info{background:var(--info)}
.legend{display:flex;flex-wrap:wrap;gap:16px;margin-top:14px;font-size:12px}
.legend .li{display:flex;align-items:center;gap:7px;color:var(--ink2)}
.legend .li .dot{width:9px;height:9px;border-radius:3px}
.legend .li b{color:var(--ink);font-variant-numeric:tabular-nums}

/* ---- generic content ---- */
.kvtable{width:100%;border-collapse:collapse;font-size:13.5px;margin:8px 0}
.kvtable td{padding:12px 4px;border-bottom:1px solid var(--hair-soft);vertical-align:top}
.kvtable td.k{color:var(--ink3);width:210px;font-weight:600}
.kvtable tr:last-child td{border-bottom:none}
.callout{border:1px solid var(--hair);border-left:3px solid var(--accent);background:var(--accent-wash);
  padding:14px 18px;border-radius:10px;margin:18px 0;font-size:13px;color:var(--ink2)}
.callout.warn{border-left-color:var(--high);background:var(--high-wash)}
.callout b{color:var(--ink)}

/* ---- findings index ---- */
.idxtable{width:100%;border-collapse:collapse;font-size:13.5px;margin-top:10px}
.idxtable th{text-align:left;font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink3);
  padding:0 12px 10px;border-bottom:1px solid var(--hair);font-weight:700}
.idxtable td{padding:13px 12px;border-bottom:1px solid var(--hair-soft);vertical-align:middle}
.idxtable tr:hover td{background:var(--wash)}
.idxtable a{font-weight:600;color:var(--ink)}.idxtable a:hover{color:var(--accent)}
.idxcount{color:var(--ink4);font-variant-numeric:tabular-nums;font-weight:700;font-size:12px}
.sevtag{display:inline-flex;align-items:center;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.04em;
  padding:3px 9px;border-radius:6px}
.sevtag.critical{color:var(--crit);background:var(--crit-wash)}
.sevtag.high{color:var(--high);background:var(--high-wash)}
.sevtag.medium{color:var(--med);background:var(--med-wash)}
.sevtag.low{color:var(--low);background:var(--low-wash)}
.sevtag.info{color:var(--info);background:var(--info-wash)}
.conftag{font-size:12px;color:var(--ink3)}

/* group heading */
.grouphead{display:flex;align-items:baseline;gap:12px;margin:40px 0 4px;padding-bottom:12px;border-bottom:2px solid var(--ink)}
.grouphead .gc{font-size:12px;color:var(--ink3);font-weight:600}

/* ---- finding card ---- */
.finding{border:1px solid var(--hair);border-radius:16px;margin:18px 0;overflow:hidden;background:var(--paper);
  box-shadow:0 1px 2px rgba(20,30,60,.04)}
.finding>.top{display:flex;gap:16px;align-items:flex-start;padding:20px 24px 18px;position:relative}
.finding>.top::before{content:"";position:absolute;left:0;top:0;bottom:0;width:5px}
.finding.critical>.top::before{background:var(--crit)}.finding.high>.top::before{background:var(--high)}
.finding.medium>.top::before{background:var(--med)}.finding.low>.top::before{background:var(--low)}.finding.info>.top::before{background:var(--info)}
.finding .ftitle{flex:1;min-width:0}
.finding .ftitle .t{font-size:19px;font-weight:750;letter-spacing:-.02em;color:var(--ink);line-height:1.25}
.finding .badges{display:flex;flex-wrap:wrap;gap:7px;margin-top:9px}
.finding .loc{font-family:var(--mono);font-size:12px;color:var(--ink2);margin-top:11px;word-break:break-all;
  background:var(--wash);border:1px solid var(--hair-soft);border-radius:8px;padding:8px 11px}
.finding .loc .m{color:var(--accent);font-weight:700}
.badge{font-size:10.5px;font-weight:650;padding:3px 10px;border-radius:999px;border:1px solid var(--hair);color:var(--ink2);background:var(--wash)}
.badge.det{color:var(--accent-ink);border-color:#d3d4f7;background:var(--accent-wash)}
.badge.v-yes,.badge.conf-confirmed{color:#127a53;border-color:#bce8d3;background:#e8faf1}
.badge.v-no{color:var(--high);border-color:#f3d6bf;background:var(--high-wash)}
.badge.conf-firm{color:var(--accent-ink);border-color:#d3d4f7;background:var(--accent-wash)}
.badge.conf-tentative{color:var(--ink3)}
.fbody{padding:2px 24px 22px}
.block{margin:20px 0}
.block>.h{font-size:11px;font-weight:800;letter-spacing:.09em;text-transform:uppercase;color:var(--ink3);margin-bottom:9px}
.prose{font-size:14px;color:var(--ink2);max-width:70ch}
.reason{font-size:14px;color:var(--ink);background:var(--wash);border:1px solid var(--hair);border-radius:11px;padding:14px 17px;max-width:none}
.chiprow{display:flex;flex-wrap:wrap;gap:8px}
.chip{font-size:11.5px;font-family:var(--mono);color:var(--ink2);background:var(--wash);border:1px solid var(--hair);border-radius:7px;padding:4px 10px}
.reflist{margin:2px 0 0;padding-left:0;list-style:none;font-size:13.5px}
.reflist li{margin:6px 0;padding-left:18px;position:relative}
.reflist li::before{content:"→";position:absolute;left:0;color:var(--accent)}
pre{font-family:var(--mono);font-size:12px;line-height:1.6;background:var(--code-bg);color:var(--code-ink);
  border-radius:12px;padding:15px 17px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;margin:0;
  box-shadow:inset 0 0 0 1px var(--code-line)}
pre.payload{background:#1a1206;color:#ffcf8b;box-shadow:inset 0 0 0 1px #3a2a10}
pre.repro{background:#08140d;color:#9ff0c0;box-shadow:inset 0 0 0 1px #14311f}
.proof{display:flex;flex-direction:column;gap:14px;margin-top:6px}
.pane{min-width:0}
.proof pre{max-height:560px;overflow:auto}
.body-print{display:none}   /* screen shows the full scrollable body; print swaps in the excerpt */
.pane .plbl{font-size:10px;font-weight:800;letter-spacing:.09em;text-transform:uppercase;color:var(--ink3);margin-bottom:7px;display:flex;justify-content:space-between}
.pane .plbl span{color:var(--accent)}
.exlabel{font-size:12.5px;font-weight:700;color:var(--ink2);margin:16px 0 8px}
.exchsep{font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--ink4);margin:20px 0 8px;padding-top:12px;border-top:1px dashed var(--hair)}
.req{color:#8fd0ff}.st2{color:#7ee0a0}.st3{color:#ffd591}.st4{color:#ffab7a}.st5{color:#ff8fa0}.mt{color:#7d8694}
.rawwrap summary{cursor:pointer;font-size:12px;color:var(--ink3);font-weight:600;padding:8px 0;list-style:none}
.rawwrap summary::-webkit-details-marker{display:none}
.rawwrap summary::before{content:"▸ ";color:var(--accent)}
.rawwrap[open] summary::before{content:"▾ "}
.remedy{font-size:14px;color:var(--ink);background:#e8faf1;border:1px solid #c6ecd6;border-radius:12px;padding:15px 18px}

/* ---- appendix ---- */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:16px 0}
.statc{border:1px solid var(--hair);border-radius:13px;padding:16px 18px;background:var(--wash)}
.statc .n{font-size:28px;font-weight:800;letter-spacing:-.02em;color:var(--ink)}
.statc .l{font-size:11px;letter-spacing:.03em;color:var(--ink3);margin-top:4px}
.engtable{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}
.engtable th{text-align:left;font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink3);padding:0 10px 9px;border-bottom:1px solid var(--hair);font-weight:700}
.engtable td{padding:11px 10px;border-bottom:1px solid var(--hair-soft)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px}
.dot.ok{background:#12a150}.dot.no{background:var(--crit)}
.footer{padding:26px 68px 46px;color:var(--ink4);font-size:11px;text-align:center;border-top:1px solid var(--hair)}

/* ---- print / PDF: each finding on its own page ---- */
@media print{
  html,body{background:#fff}
  .report{max-width:none;box-shadow:none;margin:0}
  a{color:var(--ink)}
  .cover{min-height:96vh;page-break-after:always;break-after:page}
  .section{page-break-before:always;break-before:page}
  .section.first{page-break-before:avoid;break-before:avoid}
  h2,h3{page-break-after:avoid;break-after:avoid}
  .grouphead{page-break-before:always;break-before:page}
  .finding{page-break-before:always;break-before:page}
  .nobreak{page-break-before:avoid!important;break-before:avoid!important}
  .block,.proof,.pane,.callout,.statc,.riskrow,.reason,.remedy{page-break-inside:avoid;break-inside:avoid}
  pre{white-space:pre-wrap}
  .proof pre{max-height:none;overflow:visible}   /* no scroll clipping in print */
  .body-screen{display:none}                     /* PDF: hide the full body… */
  .body-print{display:block}                     /* …and show the relevant excerpt instead */
  @page{size:A4}
}
"""

_JS = r"""
document.addEventListener('click',e=>{
  const t=e.target.closest('.finding>.top'); if(!t)return;
  const b=t.parentElement.querySelector('.fbody'); if(b) b.style.display = b.style.display==='none'?'':'none';
});
"""


# ---- rendering helpers -------------------------------------------------------

def _fmt_headers(h) -> str:
    if isinstance(h, dict):
        return "\n".join(f"{k}: {v}" for k, v in h.items())
    return str(h or "")


def _cap(text: str, limit: int | None) -> tuple[str, str]:
    """Truncate `text` to `limit` chars for concise mode; return (shown, note)."""
    text = text or ""
    if not limit or len(text) <= limit:
        return text, ""
    return text[:limit], f"\n\n[… {len(text) - limit:,} more bytes omitted in concise mode — see the full report for complete evidence]"


# Smart excerpt for the PRINT/PDF body (screen keeps the full scrollable body). Anchors on the parts
# of the body that actually prove the finding — the payload, the disclosed value, the sensitive
# marker — and collapses the rest, so a printed report shows relevant evidence instead of a mile of
# minified JS. Full bodies always remain in the xlsx/csv export.
_EXC_FULL_MAX = 1400      # bodies at/below this print whole
_EXC_CTX = 550            # chars of context around each anchor match
_EXC_HEAD, _EXC_TAIL = 480, 280   # head/tail shown when nothing anchors


def _needles(f: dict) -> list[str]:
    """Anchors to locate the relevant body region: the payload, the tested param, and notable
    tokens (emails, API keys, quoted JSON fields, long hex, Azure ACS ids) named in the finding."""
    import re
    nds: list[str] = []
    for k in ("payload", "param"):
        v = f.get(k)
        if v:
            nds.append(str(v))
    ev = " ".join(str(f.get(k) or "") for k in ("evidence", "verify_note", "detail"))
    for rx in (r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
               r"AIza[0-9A-Za-z_\-]{10,}|AKIA[0-9A-Z]{12,}|sk_[A-Za-z0-9]{10,}",
               r"\"([A-Za-z0-9_]{6,})\"", r"\b[0-9a-f]{16,}\b", r"8:acs:[0-9a-f\-]+"):
        for m in re.findall(rx, ev):
            nds.append(m if isinstance(m, str) else m[0])
    # de-dup, keep only anchors long enough to be specific
    seen, out = set(), []
    for n in nds:
        n = (n or "").strip()
        if len(n) >= 4 and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _smart_excerpt(text: str, needles: list[str]) -> tuple[str, bool]:
    """Return (excerpted_text, was_shortened). Small bodies pass through. Larger bodies are cut to a
    window around each anchor (merged), with '⋯ N chars omitted ⋯' markers; if nothing anchors, a
    head+tail slice is shown."""
    t = text or ""
    if len(t) <= _EXC_FULL_MAX:
        return t, False
    low = t.lower()
    spans: list[list[int]] = []
    for nd in needles or []:
        i = low.find(nd.lower())
        if i >= 0:
            spans.append([max(0, i - _EXC_CTX), min(len(t), i + len(nd) + _EXC_CTX)])
    if not spans:
        omitted = len(t) - _EXC_HEAD - _EXC_TAIL
        if omitted <= 0:
            return t, False
        return (t[:_EXC_HEAD] + f"\n\n      ⋯ {omitted:,} chars omitted — full body in the xlsx/csv "
                f"export ⋯\n\n" + t[-_EXC_TAIL:], True)
    spans.sort()
    merged = [spans[0]]
    for s, e in spans[1:]:
        if s <= merged[-1][1] + 100:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    out, prev = [], 0
    for s, e in merged:
        if s > prev:
            gap = s - prev
            out.append(f"      ⋯ {gap:,} {'leading ' if prev == 0 else ''}chars omitted ⋯\n")
        out.append(t[s:e])
        prev = e
    if prev < len(t):
        out.append(f"\n      ⋯ {len(t) - prev:,} trailing chars omitted — full body in the "
                   f"xlsx/csv export ⋯")
    return "".join(out), True


def _render_exchange(ex: dict, body_cap: int | None = None, needles: list[str] | None = None,
                     excerpt: bool = True) -> str:
    """Render one request/response pane pair. On SCREEN the full body shows in a scroll box; for
    PRINT/PDF a smart excerpt (anchored on the finding's proof markers) is shown instead, unless
    `excerpt` is off. Small bodies render once for both."""
    req, resp = ex.get("request", {}) or {}, ex.get("response", {}) or {}
    needles = needles or []

    rl = f"{req.get('method', 'GET')} {req.get('url', '')}"
    req_prefix = f"<span class='req'>{_esc(rl)}</span>\n" + _esc(_fmt_headers(req.get("headers")))
    req_body = str(req.get("body") or "")

    st = resp.get("status")
    stcls = f"st{str(st)[0]}" if st else "st2"
    meta = []
    if resp.get("elapsed_ms") is not None:
        meta.append(f"{resp['elapsed_ms']} ms")
    if resp.get("size") is not None:
        meta.append(f"{resp['size']} B")
    resp_prefix = (f"<span class='{stcls}'>HTTP {_esc(st) if st is not None else '—'}</span>  "
                   f"<span class='mt'>{_esc(' · '.join(meta))}</span>\n"
                   + _esc(_fmt_headers(resp.get("headers"))))
    resp_body = str(resp.get("body", "") or "")
    if resp.get("truncated"):
        resp_body += "\n\n[response truncated]"

    def _pane(label: str, sub: str, prefix: str, body: str) -> str:
        shown, bnote = _cap(body, body_cap)          # concise-mode cap first (no-op in full mode)
        full = prefix + (("\n\n" + _esc(shown) + bnote) if shown else "")
        plbl = f"<div class='plbl'>{label}<span>{sub}</span></div>"
        exbody, cut = (("", False) if not excerpt else _smart_excerpt(shown, needles))
        if not cut:
            return f"<div class='pane'>{plbl}<pre>{full}</pre></div>"
        # screen = full scrollable body; print/PDF = the relevant excerpt (toggled by @media print)
        exfull = prefix + "\n\n" + _esc(exbody) + bnote
        return (f"<div class='pane'>{plbl}"
                f"<pre class='body-screen'>{full}</pre>"
                f"<pre class='body-print'>{exfull}</pre></div>")

    label = ex.get("label")
    lblhtml = f"<div class='exlabel'>▸ {_esc(label)}</div>" if label else ""
    return (lblhtml + "<div class='proof'>"
            + _pane("Request", "attack", req_prefix, req_body)
            + _pane("Response", "evidence", resp_prefix, resp_body)
            + "</div>")


def _render_finding(f: dict, anchor: str, nobreak: bool = False, concise: bool = False,
                    excerpt: bool = True) -> str:
    """MAX DETAIL: render every field the pipeline captured for this finding.
    In concise mode, medium/low/info findings cap giant response bodies + raw output;
    critical/high always keep full evidence."""
    meta = _meta_for(f.get("category", "other"))
    sev = meta["severity"]
    # concise mode bounds giant blobs: a GENEROUS cap on crit/high (full request + headers +
    # substantial response body) and a tight cap on medium/low/info noise. The full report
    # (no --concise) keeps everything uncapped.
    if concise:
        hi = sev in ("critical", "high")
        body_cap, raw_cap = (6000, 4000) if hi else (1600, 1200)
    else:
        body_cap = raw_cap = None
    url = f.get("url", "")
    method = f.get("method", "GET")
    param = f.get("param")
    reason = f.get("evidence", "") or f.get("verify_note", "")
    tool = f.get("tool", "")
    exlog = f.get("evidence_log") or []
    detection = f.get("detection", "")
    confidence = f.get("confidence", "")
    payload = f.get("payload", "")
    raw = f.get("raw_output", "")
    repro = f.get("repro", "")
    verified = f.get("verified")

    badges = ""
    if detection:
        badges += f"<span class='badge det'>{_esc(detection)}</span>"
    if confidence:
        badges += f"<span class='badge conf-{_esc(confidence)}'>{_esc(confidence)}</span>"
    if verified is True:
        badges += "<span class='badge v-yes'>independently verified</span>"
    elif verified is False:
        badges += "<span class='badge v-no'>tool-reported, unconfirmed</span>"

    blocks = [f"<div class='block'><div class='h'>Description</div><div class='prose'>{_esc(meta['desc'])}</div></div>"]
    if reason:
        blocks.append("<div class='block'><div class='h'>Issue detail — why this is a finding</div>"
                      f"<div class='reason'>{_esc(reason)}</div></div>")
    chips = []
    if param:
        chips.append(f"<span class='chip'>parameter: {_esc(param)}</span>")
    chips.append(f"<span class='chip'>{_esc(meta['owasp'])}</span>")
    for c in meta["classes"]:
        chips.append(f"<span class='chip'>{_esc(c)}</span>")
    chips.append(f"<span class='chip'>detected by: {_esc(tool)}</span>")
    blocks.append("<div class='block'><div class='h'>Classifications</div>"
                  f"<div class='chiprow'>{''.join(chips)}</div></div>")
    if payload:
        blocks.append("<div class='block'><div class='h'>Payload</div>"
                      f"<pre class='payload'>{_esc(payload)}</pre></div>")
    if exlog:
        parts = []
        for i, ex in enumerate(exlog):
            if len(exlog) > 1:
                parts.append(f"<div class='exchsep'>exchange {i + 1} of {len(exlog)}</div>")
            parts.append(_render_exchange(ex, body_cap=body_cap, needles=_needles(f),
                                          excerpt=excerpt))
        blocks.append("<div class='block'><div class='h'>Proof — request / response "
                      f"({len(exlog)} exchange{'s' if len(exlog) != 1 else ''})</div>" + "".join(parts) + "</div>")
    elif not payload:
        blocks.append("<div class='block'><div class='h'>Evidence</div>"
                      f"<div class='reason'>{_esc(reason) or 'reported by ' + _esc(tool)}</div></div>")
    if raw and raw.strip() not in ("", "{}", "[]"):
        rawshown, rawnote = _cap(raw, raw_cap)
        blocks.append("<div class='block'><details class='rawwrap'><summary>Raw tool output "
                      f"({_esc(tool)})</summary><pre>{_esc(rawshown)}{rawnote}</pre></details></div>")
    if repro:
        blocks.append("<div class='block'><div class='h'>Reproduce</div>"
                      f"<pre class='repro'>{_esc(repro)}</pre></div>")
    if meta["refs"]:
        refs = "".join(f"<li><a href='{_esc(u)}'>{_esc(t)}</a></li>" for t, u in meta["refs"])
        blocks.append(f"<div class='block'><div class='h'>References</div><ul class='reflist'>{refs}</ul></div>")
    blocks.append(f"<div class='block'><div class='h'>Remediation</div><div class='remedy'>{_esc(meta['fix'])}</div></div>")

    nb = " nobreak" if nobreak else ""
    return f"""
    <div class="finding {sev}{nb}" id="{anchor}">
      <div class="top">
        <div class="ftitle">
          <div class="t">{_esc(meta['title'])}</div>
          <div class="badges"><span class="sevtag {sev}">{_esc(sev)}</span>{badges}</div>
          <div class="loc"><span class="m">{_esc(method)}</span> {_esc(url)}</div>
        </div>
      </div>
      <div class="fbody">{''.join(blocks)}</div>
    </div>"""


def build_report(result: dict, target: str = "", meta: dict | None = None,
                 concise: bool = False, excerpt: bool = True) -> str:
    """Render a scan result dict into a self-contained, client-grade HTML report.

    `meta` (report_meta) fills the cover / methodology: client, logo, scope, window,
    prepared_by, ref, confidential, when, profile.

    `excerpt` (default on): on screen the full request/response body shows in a scroll box; when
    PRINTED to PDF, a smart excerpt anchored on the finding's proof markers is shown instead, so the
    PDF stays manageable. Full bodies are always preserved in the xlsx/csv exports.
    """
    meta = meta or {}
    findings = result.get("findings", []) or []
    findings = sorted(findings, key=lambda f: (SEV_RANK.get(_meta_for(f.get("category", "other"))["severity"], 9),
                                               f.get("category", "")))
    sev_counts = Counter(_meta_for(f.get("category", "other"))["severity"] for f in findings)
    total = len(findings)
    from urllib.parse import urlsplit
    target = target or meta.get("target") or (findings[0]["url"] if findings else "target")
    host = urlsplit(target).netloc or target
    attn = sev_counts.get("critical", 0) + sev_counts.get("high", 0)

    groups: OrderedDict[str, list] = OrderedDict()
    for f in findings:
        groups.setdefault(f.get("category", "other"), []).append(f)

    sname = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "info"}

    # ---------- cover ----------
    logo = meta.get("logo")
    logo_html = f"<img class='logo' src='{_esc(logo)}' alt=''>" if logo else "<span class='bd'></span>"
    client = meta.get("client") or host
    confid = meta.get("confidential",
                       "CONFIDENTIAL — This report contains sensitive security findings and is intended solely "
                       "for the named recipient. Do not distribute without authorization.")
    sevstrip = "".join(
        f"<span class='sevchip'><span class='dot sd-{sname[s]}'></span><span class='n'>{sev_counts.get(s, 0)}</span> "
        f"{s.capitalize()}</span>" for s in SEV_ORDER if sev_counts.get(s, 0))
    cover_meta = [("Target scope", meta.get("scope") or target),
                  ("Assessment window", meta.get("window") or meta.get("when") or "—"),
                  ("Scan profile", (result.get("policy") or {}).get("name", meta.get("profile", "safe-deep"))),
                  ("Reference", meta.get("ref") or "—"),
                  ("Prepared by", meta.get("prepared_by") or "d4st")]
    cover_rows = "".join(f"<div class='k'>{_esc(k)}</div><div class='v'>{_esc(v)}</div>" for k, v in cover_meta)
    cover = f"""
    <section class="cover">
      <div class="brand">{logo_html}<span>d4st</span></div>
      <div class="spacer"></div>
      <div class="kicker">Web Application Security Assessment</div>
      <h1>Security Assessment Report</h1>
      <div class="client">{_esc(client)}</div>
      <div class="sevstrip">{sevstrip or "<span class='sevchip'>No findings</span>"}</div>
      <div class="meta">{cover_rows}</div>
      <div class="confid">{_esc(confid)}</div>
      <div class="spacer"></div>
      <div class="foot">Generated by d4st{(' · ' + _esc(meta.get('when'))) if meta.get('when') else ''}</div>
    </section>"""

    # ---------- executive summary ----------
    segs = "".join(
        f"<div class='seg s-{sname[s]}' style='flex:{sev_counts.get(s, 0)}' title='{s}'>{sev_counts.get(s, 0) or ''}</div>"
        for s in SEV_ORDER if sev_counts.get(s, 0))
    legend = "".join(
        f"<span class='li'><span class='dot sd-{sname[s]}'></span>{s.capitalize()} <b>{sev_counts.get(s, 0)}</b></span>"
        for s in SEV_ORDER)
    tested = (f"exercising {len(result.get('urls', []) or [])} discovered URLs across "
              f"{result.get('targets', 0)} injection targets")
    exec_html = f"""
    <section class="section first pad">
      <div class="eyebrow"><span class="num">01</span> Executive Summary <span class="rule"></span></div>
      <h2>What was found</h2>
      <p class="lead">This authenticated dynamic assessment of <b>{_esc(host)}</b> identified
        <b>{total}</b> finding{'s' if total != 1 else ''} — {_esc(_headline(sev_counts))} — {_esc(tested)}.</p>
      <div class="riskrow">
        <div class="bignum"><div class="n">{total}</div><div class="l">Total findings</div></div>
        <div class="divider"></div>
        <div class="bignum attn"><div class="n">{attn}</div><div class="l">Critical + High</div></div>
        <div class="riskbarwrap">
          <div class="riskbar">{segs or "<div class='seg s-info' style='flex:1'>0</div>"}</div>
          <div class="legend">{legend}</div>
        </div>
      </div>
    </section>"""

    # ---------- scope & methodology ----------
    pol = result.get("policy") or {}
    sess = result.get("session") or {}
    chain = result.get("chain") or []
    engines_ran = [c.get("engine") for c in chain if c.get("ran")]
    method_rows = [
        ("Target(s)", meta.get("scope") or target),
        ("Authentication", "Authenticated (captured session, re-validated during the run)" if sess
            else "Unauthenticated / as-configured"),
        ("Scan profile", pol.get("name", meta.get("profile", "safe-deep"))),
        ("Engines exercised", ", ".join(engines_ran) or "—"),
        ("Active testing", "Authorized active scanning (per-target authorization)"),
        ("Assessment window", meta.get("window") or meta.get("when") or "—"),
    ]
    mrows = "".join(f"<tr><td class='k'>{_esc(k)}</td><td>{_esc(v)}</td></tr>" for k, v in method_rows)
    sess_note = ""
    if sess.get("reauths"):
        sess_note = (f"<div class='callout warn'><b>Session note.</b> The authenticated session was "
                     f"re-established {sess['reauths']} time(s) during scanning"
                     + ("" if sess.get("authed_at_end") else ", and was not authenticated at scan end")
                     + " — some authenticated surface may be under-covered and warrants a re-run.</div>")
    method_html = f"""
    <section class="section pad">
      <div class="eyebrow"><span class="num">02</span> Scope &amp; Methodology <span class="rule"></span></div>
      <h2>How the assessment was performed</h2>
      <p class="prose">d4st chains best-in-class open-source scanners behind a single captured session,
        then deduplicates and, where possible, independently verifies each finding. Every finding in this
        report is backed by the actual request/response evidence captured during testing.</p>
      <table class="kvtable">{mrows}</table>
      {sess_note}
      <div class="callout"><b>Limitations.</b> Automated DAST covers the reachable, crawlable surface for the
        vulnerability classes tested; it does not replace a manual penetration test for business-logic flaws.
        Findings marked "tool-reported, unconfirmed" were not independently reproduced.</div>
    </section>"""

    # ---------- findings index ----------
    idx_rows = ""
    for cat, items in groups.items():
        m = _meta_for(cat)
        s = m["severity"]
        first = items[0]
        conf = first.get("confidence") or ("verified" if first.get("verified") else "")
        loc = urlsplit(items[0].get("url", "")).path or items[0].get("url", "")
        idx_rows += (f"<tr><td><a href='#f-{cat}'>{_esc(m['title'])}</a> <span class='idxcount'>×{len(items)}</span></td>"
                     f"<td class='mono' style='font-size:11.5px;color:var(--ink3)'>{_esc(loc)}</td>"
                     f"<td><span class='sevtag {s}'>{_esc(s)}</span></td>"
                     f"<td class='conftag'>{_esc(conf)}</td></tr>")
    index_html = f"""
    <section class="section pad">
      <div class="eyebrow"><span class="num">03</span> Findings Summary <span class="rule"></span></div>
      <h2>Index of findings</h2>
      <table class="idxtable">
        <thead><tr><th>Issue type</th><th>Location</th><th>Severity</th><th>Confidence</th></tr></thead>
        <tbody>{idx_rows or "<tr><td colspan='4' class='muted'>No findings.</td></tr>"}</tbody>
      </table>
    </section>"""

    # ---------- detailed findings (grouped, max detail, per-finding page break) ----------
    detail_parts = []
    for gi, (cat, items) in enumerate(groups.items()):
        m = _meta_for(cat)
        gh_cls = "grouphead" + (" nobreak" if gi == 0 else "")
        detail_parts.append(f"<h3 class='{gh_cls}' id='f-{cat}'>{_esc(m['title'])}"
                            f"<span class='gc'>{len(items)} instance{'s' if len(items) != 1 else ''}</span></h3>")
        for ii, f in enumerate(items):
            detail_parts.append(_render_finding(f, f"f-{cat}-{ii}", nobreak=(ii == 0),
                                                concise=concise, excerpt=excerpt))
    findings_html = f"""
    <section class="section pad">
      <div class="eyebrow"><span class="num">04</span> Detailed Findings <span class="rule"></span></div>
      <h2>Findings &amp; evidence</h2>
      {''.join(detail_parts) if detail_parts else "<p class='muted'>No findings were identified for the classes tested.</p>"}
    </section>"""

    # ---------- appendix ----------
    stat_cards = [("Discovered URLs", len(result.get("urls", []) or [])),
                  ("Injection targets", result.get("targets", 0)),
                  ("Findings", total),
                  ("Re-authentications", sess.get("reauths", 0))]
    scards = "".join(f"<div class='statc'><div class='n'>{_esc(v)}</div><div class='l'>{_esc(k)}</div></div>"
                     for k, v in stat_cards)
    warnings = result.get("warnings") or []
    warn_html = (f"<div class='callout warn'><b>Coverage gap.</b> Engines that did not fire: "
                 f"{_esc(', '.join(warnings))}.</div>") if warnings else ""
    eng_rows = ""
    for c in chain:
        ran = c.get("ran")
        eng_rows += (f"<tr><td><span class='dot {'ok' if ran else 'no'}'></span>{_esc(c.get('engine'))}</td>"
                     f"<td>{'ran' if ran else ('MISSING' if c.get('expected') else 'skipped')}</td>"
                     f"<td class='muted'>{_esc(c.get('note') or '—')}</td></tr>")
    appendix_html = f"""
    <section class="section pad">
      <div class="eyebrow"><span class="num">05</span> Appendix <span class="rule"></span></div>
      <h2>Coverage &amp; engine health</h2>
      <div class="stats">{scards}</div>
      {warn_html}
      <h3>Scanning engines</h3>
      <table class="engtable">
        <thead><tr><th>Engine</th><th>Status</th><th>Note</th></tr></thead>
        <tbody>{eng_rows or "<tr><td colspan='3' class='muted'>—</td></tr>"}</tbody>
      </table>
      <h3>About this report</h3>
      <p class="prose muted">Produced by d4st, a self-hosted open-source DAST appliance. Every finding is
        backed by the actual request/response evidence captured during the authorized assessment. Severity
        reflects the vulnerability class and observed impact; no aggregate letter grade is assigned.</p>
    </section>"""

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Assessment — {_esc(host)}</title>
<style>{_CSS}</style></head><body><div class="report">
  {cover}
  {exec_html}
  {method_html}
  {index_html}
  {findings_html}
  {appendix_html}
  <div class="footer">d4st · {_esc(client)} · {_esc(meta.get('ref') or host)} · confidential</div>
</div><script>{_JS}</script></body></html>"""


def render_pdf(html: str, out_path: str | None = None) -> bytes:
    """Render report HTML to a real PDF via Playwright/Chromium (already a dependency).
    Honors the print stylesheet + per-finding page breaks and adds page numbers — far more
    reliable than a manual browser print. Writes to `out_path` if given; always returns the
    PDF bytes (used by the console's PDF export endpoint)."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        raise RuntimeError("Playwright is required for PDF output. Install it with:\n"
                           "  pip install playwright && python -m playwright install chromium") from e
    footer = ("<div style=\"font-family:-apple-system,Segoe UI,Roboto,sans-serif;font-size:8px;color:#8b93a3;"
              "width:100%;padding:0 13mm;display:flex;justify-content:space-between;\">"
              "<span>d4st · confidential</span>"
              "<span>Page <span class=\"pageNumber\"></span> of <span class=\"totalPages\"></span></span></div>")
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        page = browser.new_page()
        page.set_content(html, wait_until="load")
        page.emulate_media(media="print")
        pdf_bytes = page.pdf(format="A4", print_background=True,
                             display_header_footer=True, header_template="<div></div>", footer_template=footer,
                             margin={"top": "12mm", "bottom": "16mm", "left": "0mm", "right": "0mm"})
        browser.close()
    if out_path:
        with open(out_path, "wb") as fh:
            fh.write(pdf_bytes)
    return pdf_bytes


def main(argv=None):
    import argparse
    import json
    import os
    ap = argparse.ArgumentParser(description="Render a d4st scan result JSON to a client-grade HTML/PDF report.")
    ap.add_argument("scan", help="engagement result JSON")
    ap.add_argument("-o", "--out", default=None, help="output path (.html or .pdf)")
    ap.add_argument("-t", "--target", default="", help="target URL/host label")
    ap.add_argument("--client", default=None, help="client / organisation name (cover)")
    ap.add_argument("--scope", default=None, help="scope description (cover)")
    ap.add_argument("--window", default=None, help="assessment window")
    ap.add_argument("--prepared-by", default=None, help="preparer / firm (cover)")
    ap.add_argument("--ref", default=None, help="engagement reference id")
    ap.add_argument("--logo", default=None, help="logo path or data-URI for the cover")
    ap.add_argument("--when", default=None, help="report date string")
    ap.add_argument("--pdf", action="store_true", help="also render a PDF alongside the HTML")
    ap.add_argument("--concise", action="store_true",
                    help="cap giant response bodies / raw output on medium/low/info findings "
                         "(critical & high keep full evidence)")
    ap.add_argument("--open", action="store_true", help="open the report after writing")
    a = ap.parse_args(argv)
    with open(a.scan, encoding="utf-8") as fh:
        result = json.load(fh)
    rmeta = {k: v for k, v in dict(client=a.client, scope=a.scope, window=a.window,
             prepared_by=a.prepared_by, ref=a.ref, logo=a.logo, when=a.when).items() if v is not None}
    html = build_report(result, target=a.target, meta=rmeta, concise=a.concise)
    out = a.out or (a.scan.rsplit(".", 1)[0] + "_report.html")
    if out.lower().endswith(".pdf"):
        render_pdf(html, out)
        print(f"report -> {out}")
    else:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"report -> {out}")
        if a.pdf:
            pdfp = out.rsplit(".", 1)[0] + ".pdf"
            render_pdf(html, pdfp)
            print(f"report -> {pdfp}")
    if a.open:
        import webbrowser
        webbrowser.open("file://" + os.path.abspath(out))


if __name__ == "__main__":
    main()
