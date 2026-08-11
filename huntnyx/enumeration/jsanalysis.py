from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


# ════════════════════════════════════════════════════════════════════════
#  JS ANALYSIS  ::  mine linked JavaScript for hidden endpoints + secrets
#
#  The crawl phase collects <script src> URLs but never reads them. This phase
#  fetches those .js files and pulls out two things:
#    1. endpoints / API paths that appear only inside the JS (never in links or
#       forms) — these are fed back into the same target pool Arjun/crawl feed,
#       so every downstream testing phase (XSS, SSRF, LFI, redirect …) picks
#       them up automatically;
#    2. leaked secrets (API keys, tokens, JWTs, private keys) — findings in
#       their own right, scored by severity.
# ════════════════════════════════════════════════════════════════════════


# Secrets: (label, severity, compiled regex). Ordered strong → generic.
_SECRET_SIGS = [
    ("AWS Access Key ID", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Access Key", "high",
     re.compile(r"(?i)aws.{0,24}(?:secret|sk).{0,24}['\"]([0-9a-zA-Z/+]{40})['\"]")),
    ("Google API Key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Google OAuth Client", "medium",
     re.compile(r"\b[0-9]+-[0-9A-Za-z_]{20,}\.apps\.googleusercontent\.com\b")),
    ("Slack Token", "high", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,64}\b")),
    ("Stripe Live Key", "high", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,40}\b")),
    ("GitHub Token", "high", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("Private Key block", "high",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Firebase URL", "low", re.compile(r"\bhttps://[a-z0-9\-]+\.firebaseio\.com\b")),
    ("JWT", "medium",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}\b")),
    ("Bearer token", "medium",
     re.compile(r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{20,})")),
    ("Generic secret assignment", "medium",
     re.compile(r"(?i)(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token"
                r"|client[_-]?secret|password|passwd)['\"]?\s*[:=]\s*"
                r"['\"]([0-9a-zA-Z\-_./+=]{12,})['\"]")),
]

# Endpoint-ish strings inside JS. We take quoted absolute paths and same-host
# absolute URLs; static asset noise is filtered out below.
_PATH_RE = re.compile(r"""['"`](/[A-Za-z0-9_\-./]{1,180}(?:\?[^'"`\s]{0,180})?)['"`]""")
_URL_RE = re.compile(r"""['"`](https?://[A-Za-z0-9_\-.:]+/[A-Za-z0-9_\-./]{0,180}"""
                     r"""(?:\?[^'"`\s]{0,180})?)['"`]""")
_ASSET_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".ico", ".woff",
              ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4", ".mp3", ".pdf")


def _redact(value):
    v = value or ""
    return (v[:6] + "…" + f"({len(v)} chars)") if len(v) > 8 else v


def _looks_endpoint(path):
    low = path.split("?")[0].lower()
    if low.endswith(_ASSET_EXT):
        return False
    # keep API-ish paths, anything with a query, or dynamic extensions
    if "/api" in low or "?" in path or "/graphql" in low or "/v1/" in low or "/v2/" in low:
        return True
    if re.search(r"\.(php|asp|aspx|jsp|json|do|action|cgi)$", low):
        return True
    # bare path segments (no file extension) are plausible routes
    return "." not in low.rsplit("/", 1)[-1]


def _js_sources(target, config):
    crawl = target.results.get("crawl") or {}
    js = list(crawl.get("js", []))
    # also treat any seed/known .js URLs
    for u in getattr(target, "seed_urls", []):
        if urlsplit(u).path.endswith(".js"):
            js.append(u)
    seen, out = set(), []
    for u in js:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out[: int(config.get("jsanalysis.max_files", 40) or 40)]


def phase_jsanalysis(target, config, runner):
    result = {"scanned": 0, "endpoints": [], "findings": [], "errors": []}
    sources = _js_sources(target, config)
    if not sources:
        result["errors"].append("no JS files (run crawl first)")
        UI.warn("jsanalysis: no JS to inspect")
        return result

    UI.info(f"js analysis on {len(sources)} file(s)  "
            f"{UI.c('(endpoints + secret discovery)', UI.GREY)}")
    endpoints = {}       # clean_url -> set(params)
    secrets = []
    secret_seen = set()

    for jurl in sources:
        tag = "js_" + re.sub(r"\W+", "_", jurl)[:40]
        status, _hd, body, _res = _curl_full(jurl, config, runner, tag)
        if not body:
            continue
        result["scanned"] += 1
        origin = urlsplit(jurl)
        base = f"{origin.scheme}://{origin.netloc}"

        # --- endpoints ---
        cands = set()
        for m in _PATH_RE.finditer(body):
            cands.add(urljoin(base, m.group(1)))
        for m in _URL_RE.finditer(body):
            cands.add(m.group(1))
        for u in cands:
            sp = urlsplit(u)
            if sp.netloc != origin.netloc:
                continue                       # same-host only (avoid CDNs/3rd-party)
            path = sp.path + (("?" + sp.query) if sp.query else "")
            if not _looks_endpoint(path):
                continue
            clean = f"{sp.scheme}://{sp.netloc}{sp.path}"
            params = set(parse_qs(sp.query, keep_blank_values=True).keys()) if sp.query else set()
            endpoints.setdefault(clean, set()).update(params)

        # --- secrets ---
        for label, sev, rx in _SECRET_SIGS:
            for m in rx.finditer(body):
                val = m.group(1) if m.groups() else m.group(0)
                key = (label, val)
                if key in secret_seen:
                    continue
                secret_seen.add(key)
                secrets.append({"type": label, "severity": sev,
                                "value": _redact(val), "source": jurl,
                                "url": jurl, "desc": f"{label} in JS"})
                UI.ok(f"SECRET [{sev}] {label}: {_redact(val)}")
                UI.dim(f"      -> {jurl}")

    # feed endpoints back into the pipeline (same loop Arjun/crawl use)
    fed = 0
    cap = int(config.get("jsanalysis.max_endpoints_fed", 80) or 80)
    existing = {(urlsplit(pe['url']).path, tuple(sorted(pe['params'])))
                for pe in target.param_endpoints}
    crawl = target.results.get("crawl")
    crawl_urls = set(crawl.get("urls", [])) if isinstance(crawl, dict) else set()
    for clean, params in sorted(endpoints.items()):
        plist = sorted(params)
        result["endpoints"].append({"url": clean, "params": plist})
        crawl_urls.add(clean)
        if clean not in target.seed_urls:
            target.seed_urls.append(clean)
        if plist:
            sig = (urlsplit(clean).path, tuple(plist))
            if sig not in existing and fed < cap:
                target.param_endpoints.append({"url": clean, "params": plist})
                existing.add(sig)
                fed += 1
    if isinstance(crawl, dict):
        crawl["urls"] = sorted(crawl_urls)

    if result["endpoints"]:
        UI.ok(f"js: {len(result['endpoints'])} endpoint(s), +{fed} queued for active checks")
    if secrets:
        UI.warn(f"js: {len(secrets)} secret(s) found")
    if not result["endpoints"] and not secrets:
        UI.dim(f"      nothing notable in {result['scanned']} JS file(s)")
    result["findings"] = secrets
    return result


def _r_jsanalysis(d):
    lines = _sec("JS ANALYSIS")
    lines.append(f"  scanned {d.get('scanned', 0)} JS file(s)")
    eps = d.get("endpoints", [])
    if eps:
        lines.append("  endpoints (fed into active checks):")
        for e in eps:
            p = f"  [{', '.join(e['params'])}]" if e.get("params") else ""
            lines.append(f"    {e['url']}{p}")
    secrets = d.get("findings", [])
    if secrets:
        lines.append("  secrets:")
        for s in secrets:
            lines.append(f"    [{s['severity']}] {s['type']}: {s['value']}")
            lines.append(f"        {s['source']}")
    if not eps and not secrets:
        note = d.get("errors", [])
        lines.append("  " + (note[0] if note else "nothing notable found"))
    return lines + [""]
