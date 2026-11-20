"""Intruder engine — a generic §position§ × payload sweep.

`sweep()` is the reusable form of the per-position substitution loop the injection probes use
(`activetests._req`): mark positions as §name§ in a URL and/or body template, give each position a
payload list, pick an attack mode, and it sends the matrix throttled with `safety.AdaptiveThrottle`,
flagging status/length outliers (the Intruder "sort by length" tell). Full evidence is attached only
to the notable rows so a large sweep stays cheap to carry.

Read-only by default (same gate as replay()); a neutral `policy` hook runs before every request so
an outside driver can inject its own pre-request check without this module knowing about it.
"""

from __future__ import annotations

import re
from itertools import product

from .evidence import exchange
from .safety import (AdaptiveThrottle, browser_headers, is_auth_endpoint,
                     is_session_destroying_endpoint, is_state_changing)

_READ_ONLY_VERBS = {"GET", "HEAD", "OPTIONS"}
_POS = re.compile(r"§([A-Za-z0-9_.\-]+)§")


def _merge_headers(url: str, headers: dict | None, session, cookie: str) -> dict:
    h = browser_headers()
    if session is not None:
        h.update(dict(getattr(session, "headers", {}) or {}))
        try:
            ck = session.cookie_header(url)
            if ck:
                h["Cookie"] = ck
        except Exception:  # noqa: BLE001
            pass
    if cookie:
        h["Cookie"] = cookie
    if headers:
        h.update(headers)
    return h


def _substitute(template: str, values: dict) -> str:
    """Replace every §name§ marker with values[name] (missing markers -> empty)."""
    return _POS.sub(lambda m: str(values.get(m.group(1), "")), template or "")


def _combinations(positions: dict, mode: str, max_requests: int) -> list[dict]:
    """The list of {position: payload} assignments this mode produces."""
    names = list(positions)
    baseline = {n: (positions[n][0] if positions[n] else "") for n in names}
    combos: list[dict] = []
    if mode == "sniper":
        # vary one position at a time; all others at their baseline value
        for n in names:
            for pay in positions[n]:
                c = dict(baseline)
                c[n] = pay
                combos.append(c)
    elif mode == "pitchfork":
        # zip the payload lists in lockstep (shortest list bounds the run)
        depth = min((len(positions[n]) for n in names), default=0)
        for i in range(depth):
            combos.append({n: positions[n][i] for n in names})
    elif mode in ("cluster-bomb", "clusterbomb"):
        for tup in product(*(positions[n] for n in names)):
            combos.append(dict(zip(names, tup)))
    else:
        raise ValueError(f"unknown mode {mode!r} (use sniper | pitchfork | cluster-bomb)")
    return combos[:max_requests]


def sweep(method: str, url_template: str, positions: dict, *,
          mode: str = "sniper", body_template: str = "", headers: dict | None = None,
          session=None, cookie: str = "", max_requests: int = 500,
          base_delay: float = 0.15, timeout: float = 12.0, verify: bool = False,
          allow_state_changing: bool = False, policy=None) -> dict:
    """Burp-Intruder-style sweep. Positions are marked §name§ in url_template / body_template and
    `positions` maps each name to its payload list.

    modes: 'sniper' (vary one position at a time, others baseline),
           'pitchfork' (zip the payload lists in lockstep),
           'cluster-bomb' (cartesian product, capped at max_requests).

    Throttled with safety.AdaptiveThrottle(base_delay) (backs off on 429/503). Read-only by default
    (write verb or destructive/auth path refused unless allow_state_changing=True). A DELETE verb or
    a session-destroying endpoint is HARD-REFUSED even with allow_state_changing=True (a sweep never
    auto-fires a deletion / logout). `policy`, if given, is called policy(method, url) before each
    request; raising aborts that request.

    Returns: {ok, mode, total, sent, results:[{payloads, status, size, elapsed_ms, anomalous}],
              notable:[...]} — `anomalous` marks status/length outliers vs the modal response; full
    evidence.exchange is attached only to notable rows.
    """
    import httpx

    m = (method or "GET").upper()
    # HARD RULE (mirrors engagement.capture_full_evidence): a sweep fires N requests, so a DELETE
    # verb is NEVER auto-fired even with allow_state_changing=True. Deletion stays manual elsewhere.
    if m == "DELETE":
        raise ValueError(
            f"{m} sweep is refused outright: DELETE is never auto-fired by a primitive "
            "(a sweep fires many requests); allow_state_changing cannot authorize it")
    if not allow_state_changing and (m not in _READ_ONLY_VERBS):
        raise ValueError(f"{m} sweep is not read-only; pass allow_state_changing=True to authorize it")

    combos = _combinations(positions, mode, max_requests)
    merged_static = _merge_headers(url_template, headers, session, cookie)
    thr = AdaptiveThrottle(base_delay=base_delay)

    rows: list[dict] = []
    resps: list = []           # parallel to rows; the httpx.Response (or None) for notable proof
    sent = 0
    with httpx.Client(verify=verify, follow_redirects=False, timeout=timeout) as c:
        for combo in combos:
            url = _substitute(url_template, combo)
            body = _substitute(body_template, combo) if body_template else ""
            # A session-destroying (logout) endpoint is HARD-REFUSED even on opt-in.
            if is_session_destroying_endpoint(url):
                raise ValueError(
                    f"{url} is a session-destroying endpoint; a primitive never auto-fires it")
            if not allow_state_changing and (is_state_changing(url) or is_auth_endpoint(url)):
                raise ValueError(
                    f"{url} is a destructive/auth path; pass allow_state_changing=True to authorize it")
            if policy is not None:
                policy(m, url)
            thr.wait()
            try:
                r = c.request(m, url, headers=merged_static, content=(body.encode() if body else None))
            except Exception as exc:  # noqa: BLE001 - record the failure, keep sweeping
                rows.append({"payloads": combo, "status": None, "size": 0,
                             "elapsed_ms": None, "error": str(exc), "anomalous": True})
                resps.append(None)
                continue
            thr.record(r.status_code)
            sent += 1
            rows.append({
                "payloads": combo,
                "status": r.status_code,
                "size": len(r.content or b""),
                "elapsed_ms": int(r.elapsed.total_seconds() * 1000) if r.elapsed else None,
                "anomalous": False,
            })
            resps.append(r)

    # modal status + typical size => mark outliers (the Intruder length/status tell)
    statuses = [row["status"] for row in rows if row["status"] is not None]
    sizes = [row["size"] for row in rows if row["status"] is not None]
    modal_status = max(set(statuses), key=statuses.count) if statuses else None
    modal_size = sorted(sizes)[len(sizes) // 2] if sizes else 0      # median
    notable: list[dict] = []
    for row, r in zip(rows, resps):
        if row.get("error"):
            notable.append({**row})
            continue
        off_status = row["status"] != modal_status
        off_size = modal_size > 0 and abs(row["size"] - modal_size) / max(row["size"], modal_size) > 0.30
        if off_status or off_size:
            row["anomalous"] = True
            entry = {**row}
            if r is not None:
                entry["exchange"] = exchange(
                    f"sweep hit — {row['payloads']}", r,
                    req_body=_substitute(body_template, row["payloads"]) if body_template else "")
            notable.append(entry)

    return {
        "ok": True,
        "mode": mode,
        "total": len(combos),
        "sent": sent,
        "modal_status": modal_status,
        "results": rows,
        "notable": notable,
    }
