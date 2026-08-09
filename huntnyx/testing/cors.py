from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403

# ════════════════════════════════════════════════════════════════════════
#  CORS MISCONFIGURATION  ::  proof-based, unforgeable-canary origin probing
#
#  Sends crafted `Origin` headers and inspects the reflected
#  `Access-Control-Allow-Origin` (ACAO) / `Access-Control-Allow-Credentials`
#  (ACAC) response headers. Confirmation is by PROOF, not inference:
#
#    • a RANDOM canary origin (…canary-oob.test) can never be hardcoded, so
#      ACAO echoing it back is unforgeable evidence the app reflects ANY origin;
#    • the target-derived bypass origins (suffix / prefix / null / http) are all
#      hosts an ATTACKER could actually register or control, so reflecting one
#      is a genuine, exploitable finding — not a theoretical string match.
#
#  Severity ladder (highest wins per endpoint):
#    CRITICAL : attacker-controllable origin reflected  +  ACAC: true
#               → authenticated cross-origin data theft
#    HIGH     : attacker-controllable origin reflected (no creds)
#               → cross-origin read of any non-credentialed response
#    MEDIUM   : ACAO: *  with ACAC: true (invalid combo, but a real misconfig) /
#               http:// origin trusted on an https resource (MITM downgrade)
#    INFO     : ACAO: *  without credentials (often an intentional public API)
#
#  Bypass classes probed per endpoint:
#    reflected-arbitrary   Origin: https://<rand>.canary-oob.test
#    null-origin           Origin: null
#    suffix-bypass         Origin: https://<host>.<canary>     (naive startsWith)
#    prefix/substr-bypass  Origin: https://<rand><host>        (naive endsWith/in)
#    http-downgrade        Origin: http://<host>               (https targets only)
#    wildcard              ACAO: *  (classified by the ACAC flag)
# ════════════════════════════════════════════════════════════════════════


_SEV_RANK = {"info": 0, "medium": 1, "high": 2, "critical": 3}


def _cors_bases(target):
    """Every distinct (scheme, netloc, path) worth a CORS probe: web roots,
    crawled URLs, discovered content dirs, and known parameterized endpoints.
    CORS policy is frequently endpoint-scoped (e.g. only /api/*), so we don't
    collapse to host-level — we test each distinct path once."""
    bases, seen = [], set()

    def add(u):
        if not u:
            return
        sp = urlsplit(u)
        if not sp.scheme or not sp.netloc:
            return
        clean = urlunsplit((sp.scheme, sp.netloc, sp.path or "/", "", ""))
        sig = (sp.netloc, sp.path or "/")
        if sig in seen:
            return
        seen.add(sig)
        bases.append(clean)

    for s in target.web_services:
        add(s.url)
    crawl = target.results.get("crawl") or {}
    for u in crawl.get("urls", []):
        add(u)
    content = target.results.get("content") or {}
    for e in content.get("services", []):
        b = e.get("url", "")
        for f in e.get("found", []):
            if (f.get("status") or 0) in (200, 301, 302, 401, 403):
                add(b.rstrip("/") + "/" + (f.get("path") or "").lstrip("/"))
    for pe in _active_targets(target):
        add(pe.get("url"))
    return bases


def _acao_reflects(acao, origin):
    """True only when ACAO echoes our exact attacker-controlled origin."""
    if not acao:
        return False
    # _curl_full may join duplicate headers with '; ' — take the first token.
    first = acao.split(";")[0].strip().lower()
    return first == origin.strip().lower()


def _acac_true(acac):
    return bool(acac) and "true" in acac.lower()


def _probe(base, config, runner, origin, tag, method="GET"):
    """Fire one request with a crafted Origin; return (acao, acac_bool)."""
    extra = ["-H", f"Origin: {origin}"]
    if method == "OPTIONS":
        extra = ["-X", "OPTIONS",
                 "-H", f"Origin: {origin}",
                 "-H", "Access-Control-Request-Method: GET",
                 "-H", "Access-Control-Request-Headers: authorization,content-type"]
    _st, headers, _body, _res = _curl_full(base, config, runner, tag, extra=extra)
    return headers.get("access-control-allow-origin", ""), \
        _acac_true(headers.get("access-control-allow-credentials", ""))


def _classes_for(base, canary):
    """Build the ordered probe list for one endpoint."""
    sp = urlsplit(base)
    host = sp.netloc.split(":")[0]
    is_https = sp.scheme == "https"
    probes = [
        ("reflected-arbitrary-origin", f"https://{canary}",           "high"),
        ("null-origin",                "null",                        "high"),
        ("suffix-bypass",              f"https://{host}.{canary}",    "high"),
        ("prefix-substring-bypass",    f"https://{_rand(6)}{host}",   "high"),
    ]
    if is_https:
        probes.append(("insecure-http-origin", f"http://{host}",      "medium"))
    return probes


def phase_cors(target, config, runner):
    target.ensure_web_services(config, runner)
    result = {"findings": [], "errors": []}
    bases = _cors_bases(target)
    if not bases:
        result["errors"].append("no endpoints to probe (run crawl/content first)")
        UI.warn("cors: nothing to test")
        return result

    canary = f"cors{_rand(10)}.canary-oob.test"
    cap = int(config.get("active.max_endpoints", 60) or 60)
    delay = float(config.get("active.delay", 0) or 0)
    tested = 0
    UI.info("CORS misconfiguration scan")
    UI.dim(f"      probing {min(len(bases), cap)} endpoint(s) with canary origin")

    for base in bases[:cap]:
        tested += 1
        btag = re.sub(r"\W+", "_", base)[:40]

        for cls, origin, sev in _classes_for(base, canary):
            acao, acac = _probe(base, config, runner, origin, f"cors_{cls}_{btag}")
            # preflight fallback for the arbitrary-origin class (APIs that only
            # emit CORS headers on the OPTIONS preflight)
            if not acao and cls == "reflected-arbitrary-origin":
                acao, acac = _probe(base, config, runner, origin,
                                    f"cors_pre_{btag}", method="OPTIONS")
            if not _acao_reflects(acao, origin):
                if delay:
                    time.sleep(delay)
                continue
            severity = "critical" if acac else sev
            result["findings"].append({
                "url": base, "class": cls, "origin": origin,
                "acao": acao, "acac": acac, "severity": severity,
                "confirmed": True,
            })
            tag = " +credentials" if acac else ""
            UI.ok(f"CORS [{severity.upper()}] {cls}{tag}: {base}")
            UI.dim(f"      Origin: {origin}  ->  ACAO: {acao}"
                   + ("  ACAC: true" if acac else ""))
            if delay:
                time.sleep(delay)

        # wildcard check (single request, benign origin)
        wacao, wacac = _probe(base, config, runner, f"https://{canary}",
                              f"cors_wild_{btag}")
        if wacao.split(";")[0].strip() == "*":
            severity = "medium" if wacac else "info"
            confirmed = bool(wacac)
            result["findings"].append({
                "url": base, "class": "wildcard-acao", "origin": "*",
                "acao": "*", "acac": wacac, "severity": severity,
                "confirmed": confirmed,
            })
            if wacac:
                UI.warn(f"CORS [MEDIUM] wildcard + credentials: {base}")
            else:
                UI.dim(f"      wildcard ACAO: * (no creds — often intentional): {base}")

    # dedup: keep the single highest-severity finding per (url, class)
    best = {}
    for f in result["findings"]:
        k = (f["url"], f["class"])
        cur = best.get(k)
        if cur is None or _SEV_RANK[f["severity"]] > _SEV_RANK[cur["severity"]]:
            best[k] = f
    result["findings"] = sorted(
        best.values(),
        key=lambda f: (-_SEV_RANK[f["severity"]], f["url"], f["class"]))

    confirmed = [f for f in result["findings"] if f["confirmed"]]
    info = [f for f in result["findings"] if not f["confirmed"]]
    if confirmed:
        UI.ok(f"found {len(confirmed)} confirmed CORS misconfiguration(s)")
    if info:
        UI.warn(f"{len(info)} informational CORS note(s)")
    if not result["findings"]:
        UI.dim(f"      no CORS misconfigurations found ({tested} endpoint(s) tested)")
    return result


def _r_cors(d):
    lines = _sec("CORS MISCONFIGURATION")
    fs = d.get("findings", [])
    if not fs:
        note = d.get("errors", [])
        lines.append("  " + ("none found" if not note else note[0]))
        return lines + [""]
    for f in fs:
        tag = "[CONFIRMED]" if f["confirmed"] else "[info]"
        cred = " +credentials" if f.get("acac") else ""
        lines.append(f"  {tag} {f['severity'].upper()} · {f['class']}{cred}")
        lines.append(f"      endpoint : {f['url']}")
        lines.append(f"      Origin   : {f['origin']}")
        lines.append(f"      ACAO     : {f['acao']}"
                     + ("   ACAC: true" if f.get("acac") else ""))
        lines.append("")
    return lines
