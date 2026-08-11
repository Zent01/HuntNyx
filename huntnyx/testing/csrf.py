from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


# ════════════════════════════════════════════════════════════════════════
#  CSRF  ::  state-changing POST forms with no anti-CSRF protection
#
#  CSRF can't be fully confirmed without a real cross-origin browser test, so
#  this phase reports observable, well-defined weaknesses and labels them as
#  review items:
#    • a state-changing POST form that carries NO anti-CSRF token field, and
#    • whether the session cookie sets SameSite (which mitigates CSRF).
#  Severity is medium when nothing mitigates it, downgraded to low when the
#  session cookie is SameSite=Lax/Strict (browser already blocks the attack).
# ════════════════════════════════════════════════════════════════════════


_TOKEN_RE = re.compile(
    r"(?i)(?:csrf|xsrf|_token\b|authenticity_token|anti.?forgery|"
    r"__requestverificationtoken|nonce|form_key|synchronizer)")

# fields that are NOT anti-CSRF tokens even if they contain 'token'
_TOKEN_FALSE = re.compile(r"(?i)(?:g-recaptcha|captcha|h-captcha)")

_SESSION_COOKIE_RE = re.compile(
    r"(?i)(?:sess|sid|phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|"
    r"auth|token|login|remember)")


def _has_token(inputs):
    for name in inputs or []:
        n = str(name)
        if _TOKEN_RE.search(n) and not _TOKEN_FALSE.search(n):
            return True
    return False


def _samesite_state(target, config, runner):
    """Fetch a web root once and inspect Set-Cookie for a session cookie's
    SameSite attribute. Returns 'lax'/'strict'/'none'/'missing'/'unknown'."""
    for svc in target.web_services:
        tag = "csrf_cookie_" + svc.key().replace(":", "_")
        _st, headers, _b, _r = _curl_full(svc.url, config, runner, tag)
        setc = headers.get("set-cookie", "")
        if not setc:
            continue
        # _curl_full joins duplicate headers with '; '; scan the whole blob
        low = setc.lower()
        if not _SESSION_COOKIE_RE.search(low):
            # still consider any cookie
            pass
        m = re.search(r"samesite\s*=\s*(lax|strict|none)", low)
        if m:
            return m.group(1)
        return "missing"
    return "unknown"


def phase_csrf(target, config, runner):
    result = {"findings": [], "errors": []}
    forms = _post_forms(target)
    if not forms:
        result["errors"].append("no POST forms (run crawl first)")
        UI.warn("csrf: no state-changing forms to inspect")
        return result

    samesite = _samesite_state(target, config, runner)
    UI.info("csrf scan (anti-CSRF token + SameSite)")
    UI.dim(f"      session cookie SameSite: {samesite}")

    cap = int(config.get("csrf.max_forms", 60) or 60)
    seen = set()
    for fm in forms[:cap]:
        action = fm.get("action")
        inputs = fm.get("inputs", [])
        if not action or action in seen:
            continue
        seen.add(action)
        if _has_token(inputs):
            continue                      # protected — skip
        mitigated = samesite in ("lax", "strict")
        severity = "low" if mitigated else "medium"
        note = (f"SameSite={samesite} mitigates most CSRF"
                if mitigated else
                (f"session cookie SameSite {samesite} — CSRF likely exploitable"
                 if samesite in ("none", "missing") else
                 "no anti-CSRF token in form"))
        result["findings"].append({
            "url": action, "method": "POST", "severity": severity,
            "review": True, "inputs": list(inputs),
            "samesite": samesite, "note": note,
        })
        UI.warn(f"CSRF [{severity}] no token: POST {action}")
        UI.dim(f"      inputs: {', '.join(map(str, inputs))[:120]}")
        UI.dim(f"      {note}")

    if not result["findings"]:
        UI.dim(f"      no unprotected POST forms ({len(forms)} inspected)")
    else:
        UI.warn(f"{len(result['findings'])} form(s) without anti-CSRF token (verify manually)")
    return result


def _r_csrf(d):
    lines = _sec("CSRF (cross-site request forgery)")
    fs = d.get("findings", [])
    if not fs:
        note = d.get("errors", [])
        lines.append("  " + ("none found" if not note else note[0]))
        return lines + [""]
    for f in fs:
        lines.append(f"  [review] {f['severity'].upper()}  POST {f['url']}")
        lines.append(f"      inputs   : {', '.join(map(str, f.get('inputs', [])))}")
        lines.append(f"      SameSite : {f.get('samesite','unknown')}")
        lines.append(f"      note     : {f.get('note','')}")
        lines.append("")
    return lines
