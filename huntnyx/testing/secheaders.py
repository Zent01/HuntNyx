from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403

# ════════════════════════════════════════════════════════════════════════
#  SECURITY HEADERS + COOKIE HYGIENE  ::  passive, deterministic, exhaustive
#
#  Reads the FINAL response headers of each discovered web service (follows
#  redirects so an http→https hop can't hide the real app's headers) and
#  reports every deviation from current best practice as a severity-tagged,
#  byte-for-byte objective fact. There is no inference here, so there are no
#  false positives — only presence/absence and literal value validation.
#
#  Coverage:
#    Transport   HSTS (max-age strength, includeSubDomains, preload)
#    Injection   CSP (missing / report-only-only / unsafe-inline / unsafe-eval /
#                 wildcard / http: / data: in script-src / object-src / base-uri),
#                X-Content-Type-Options
#    Framing     X-Frame-Options vs CSP frame-ancestors (clickjacking)
#    Privacy     Referrer-Policy (missing / leaky value), Permissions-Policy
#    Isolation   COOP / COEP / CORP  (Spectre / cross-origin isolation)
#    Legacy      X-XSS-Protection (flags the dangerous "1" enabling form)
#    Disclosure  Server version, X-Powered-By, X-AspNet(-Mvc)-Version, X-Runtime,
#                Via, X-Generator, X-Drupal-Cache, X-Backend/Served-By
#    Caching     cacheable response that also sets a cookie (sensitive caching)
#    Cookies     HttpOnly / Secure / SameSite, SameSite=None-without-Secure,
#                session cookie without HttpOnly (escalated), and the
#                __Host-/__Secure- cookie-prefix contracts
#
#  Note: this is header/cookie hygiene — it does NOT find application logic
#  or injection flaws. Those are the job of the xss/ssti/cmdi/xxe/traversal/
#  sqlmap/redirect/cors modules and the confidence engine.
# ════════════════════════════════════════════════════════════════════════


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}

_INFO_LEAK_HEADERS = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                      "x-generator", "x-drupal-cache", "x-runtime", "via",
                      "x-backend-server", "x-served-by", "x-amz-cf-id")

# Server header carrying a version (e.g. "Apache/2.4.41") leaks; a bare name
# ("nginx") does not.
_SERVER_VERSION_RE = re.compile(r"/\d")

_HSTS_MIN = 31536000          # 1 year (current baseline / preload requirement)
_SESSION_COOKIE_RE = re.compile(r"(sess|sid|token|auth|jwt|login|csrf|xsrf)", re.I)
_LEAKY_REFERRER = ("unsafe-url", "no-referrer-when-downgrade")


def _full_headers(url, config, runner, tag):
    """Fetch FINAL-response headers following redirects. Set-Cookie is preserved
    as a list (curl emits one line per cookie)."""
    timeout = config.get("timeouts.curl", 15)
    res = runner.run(["curl", "-s", "-D", "-", "-o", "/dev/null", "-k", "-L",
                      "--max-redirs", "10", "--max-time", str(timeout),
                      *auth_curl(config), url],
                     log_name=f"secheaders_{tag}", timeout=timeout + 5)
    status, headers, cookies = "", {}, []
    for line in (res.stdout or "").splitlines():
        m = re.match(r"HTTP/\S+\s+(\d{3})", line)
        if m:                                   # new response block -> reset
            status, headers, cookies = m.group(1), {}, []
            continue
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if k == "set-cookie":
            cookies.append(v)
        else:
            headers[k] = (headers[k] + ", " + v) if k in headers else v
    return status, headers, cookies


def _add(findings, sev, msg):
    findings.append({"sev": sev, "msg": msg})


def _check_hsts(h, is_https, F):
    if not is_https:
        return
    hsts = h.get("strict-transport-security")
    if not hsts:
        _add(F, "medium", "missing Strict-Transport-Security (HSTS)")
        return
    low = hsts.lower()
    m = re.search(r"max-age\s*=\s*(\d+)", low)
    if not m or int(m.group(1)) == 0:
        _add(F, "medium", "HSTS present but max-age is 0/absent (disables HSTS)")
    elif int(m.group(1)) < _HSTS_MIN:
        _add(F, "low", f"HSTS max-age below 1 year ({m.group(1)}s)")
    if "includesubdomains" not in low:
        _add(F, "low", "HSTS missing includeSubDomains")
    if "preload" not in low:
        _add(F, "info", "HSTS not preload-eligible (no preload directive)")


def _check_csp(h, F):
    enforce = h.get("content-security-policy")
    ro = h.get("content-security-policy-report-only")
    if not enforce and not ro:
        _add(F, "medium", "missing Content-Security-Policy")
        return
    if not enforce and ro:
        _add(F, "medium", "CSP is Report-Only (not enforced)")
    csp = (enforce or ro or "").lower()
    if "unsafe-inline" in csp:
        _add(F, "medium", "CSP allows 'unsafe-inline' (defeats XSS mitigation)")
    if "unsafe-eval" in csp:
        _add(F, "medium", "CSP allows 'unsafe-eval'")
    if re.search(r"(default|script)-src[^;]*(\s|:)\*", csp):
        _add(F, "medium", "CSP script/default-src uses wildcard *")
    if re.search(r"(default|script)-src[^;]*http:", csp):
        _add(F, "low", "CSP allows insecure http: script source")
    if re.search(r"script-src[^;]*data:", csp):
        _add(F, "medium", "CSP allows data: in script-src (XSS vector)")
    if "object-src" not in csp:
        _add(F, "low", "CSP missing object-src 'none'")
    if "base-uri" not in csp:
        _add(F, "low", "CSP missing base-uri (base-tag injection)")
    if "frame-ancestors" not in csp:
        _add(F, "info", "CSP missing frame-ancestors (relies on X-Frame-Options)")


def _check_framing(h, F):
    xfo = h.get("x-frame-options", "").strip()
    csp = h.get("content-security-policy", "").lower()
    if not xfo and "frame-ancestors" not in csp:
        _add(F, "medium", "no clickjacking protection "
                          "(X-Frame-Options / CSP frame-ancestors both absent)")
    elif xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
        if xfo.upper().startswith("ALLOW-FROM"):
            _add(F, "low", f"X-Frame-Options uses deprecated ALLOW-FROM ({xfo})")
        else:
            _add(F, "low", f"X-Frame-Options non-standard value: {xfo}")


def _check_misc(h, F):
    xcto = h.get("x-content-type-options", "").strip().lower()
    if xcto != "nosniff":
        _add(F, "low", "missing X-Content-Type-Options: nosniff")

    rp = h.get("referrer-policy")
    if rp is None:
        _add(F, "low", "missing Referrer-Policy")
    elif rp.strip().lower() in _LEAKY_REFERRER:
        _add(F, "low", f"Referrer-Policy leaks referrer: {rp}")

    if "permissions-policy" not in h and "feature-policy" not in h:
        _add(F, "info", "missing Permissions-Policy")

    if "cross-origin-opener-policy" not in h:
        _add(F, "info", "missing Cross-Origin-Opener-Policy (COOP)")
    if "cross-origin-resource-policy" not in h:
        _add(F, "info", "missing Cross-Origin-Resource-Policy (CORP)")

    xxp = h.get("x-xss-protection", "").strip()
    if xxp.startswith("1"):
        _add(F, "low", f"legacy X-XSS-Protection enabled ({xxp}) - can introduce "
                       "issues; modern guidance is '0'")


def _check_disclosure(h, F):
    srv = h.get("server", "")
    if srv and _SERVER_VERSION_RE.search(srv):
        _add(F, "info", f"Server discloses version: {srv}")
    for name in _INFO_LEAK_HEADERS:
        if name in h:
            _add(F, "info", f"technology-disclosure header {name}: {h[name]}")


def _check_caching(h, cookies, F):
    if not cookies:
        return
    cc = h.get("cache-control", "").lower()
    pragma = h.get("pragma", "").lower()
    if "no-store" in cc or "private" in cc or "no-cache" in cc or "no-cache" in pragma:
        return
    _add(F, "medium", "response sets a cookie but is cacheable "
                      "(no Cache-Control: no-store/private) - sensitive caching risk")


def _check_cookies(cookies, is_https, F):
    for raw in cookies:
        name = raw.split("=", 1)[0].strip() or "(unnamed)"
        low = raw.lower()
        has_httponly = "httponly" in low
        has_secure = "secure" in low
        sm = re.search(r"samesite\s*=\s*(\w+)", low)
        samesite = sm.group(1) if sm else ""

        issues = []
        if not has_httponly:
            issues.append("HttpOnly")
        if is_https and not has_secure:
            issues.append("Secure")
        if not samesite:
            issues.append("SameSite")
        if issues:
            sev = "high" if (_SESSION_COOKIE_RE.search(name) and "HttpOnly" in issues) \
                else "low"
            _add(F, sev, f"cookie [{name}] missing: {', '.join(issues)}")

        if samesite == "none" and not has_secure:
            _add(F, "medium", f"cookie [{name}] SameSite=None without Secure (invalid)")

        if name.startswith("__Host-"):
            bad = []
            if not has_secure:
                bad.append("Secure")
            if "domain=" in low:
                bad.append("no Domain")
            if not re.search(r"path\s*=\s*/(\s|;|$)", low):
                bad.append("Path=/")
            if bad:
                _add(F, "medium",
                     f"cookie [{name}] violates __Host- prefix (needs {', '.join(bad)})")
        elif name.startswith("__Secure-") and not has_secure:
            _add(F, "medium", f"cookie [{name}] violates __Secure- prefix (needs Secure)")


def phase_secheaders(target, config, runner):
    target.ensure_web_services(config, runner)
    result = {"services": [], "errors": []}
    if not target.web_services:
        result["errors"].append("no web services to inspect")
        UI.warn("secheaders: no web services")
        return result

    grand = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for svc in target.web_services:
        tag = svc.key().replace(":", "_")
        UI.info(f"security headers {UI.c(svc.url, UI.WHITE)}")
        status, headers, cookies = _full_headers(svc.url, config, runner, tag)
        if not status and not headers:
            UI.warn(f"secheaders {svc.url}: no response")
            result["errors"].append(f"no response from {svc.url}")
            continue
        is_https = svc.scheme == "https"

        F = []
        _check_hsts(headers, is_https, F)
        _check_csp(headers, F)
        _check_framing(headers, F)
        _check_misc(headers, F)
        _check_disclosure(headers, F)
        _check_caching(headers, cookies, F)
        _check_cookies(cookies, is_https, F)

        F.sort(key=lambda x: -_SEV_RANK[x["sev"]])
        for f in F:
            grand[f["sev"]] += 1

        result["services"].append({"url": svc.url, "status": status, "findings": F})

        if not F:
            UI.ok(f"{svc.url}: all recommended headers present")
            continue
        for f in F:
            if f["sev"] in ("high", "medium", "low"):
                UI.warn(f"[{f['sev']}] {f['msg']}")
            else:
                UI.dim(f"      [info] {f['msg']}")

    UI.info(f"secheaders: {grand['high']} high · {grand['medium']} medium · "
            f"{grand['low']} low · {grand['info']} info")
    return result


def _r_secheaders(d):
    lines = _sec("SECURITY HEADERS")
    svcs = d.get("services", [])
    if not svcs:
        note = d.get("errors", [])
        lines.append("  " + ("nothing inspected" if not note else note[0]))
        return lines + [""]
    label = {"high": "HIGH  ", "medium": "MEDIUM", "low": "LOW   ", "info": "INFO  "}
    for s in svcs:
        st = f" (HTTP {s['status']})" if s.get("status") else ""
        lines.append(f"  {s['url']}{st}")
        F = s.get("findings", [])
        if not F:
            lines.append("      all recommended headers present")
            lines.append("")
            continue
        for f in F:
            lines.append(f"      [{label[f['sev']]}] {f['msg']}")
        lines.append("")
    return lines
