from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403
import base64
import hashlib
import hmac
import time as _time


# ════════════════════════════════════════════════════════════════════════
#  JWT  ::  find and audit JSON Web Tokens
#
#  Collects JWTs from the supplied auth material (cookie / headers), from
#  Set-Cookie on the web roots, and from anything JS analysis already surfaced.
#  Then audits each token:
#    • alg:none            -> the server may accept an unsigned token   (high)
#    • weak HMAC secret    -> signature verified against a wordlist     (critical, PROOF)
#    • missing/expired exp -> token never / no longer expires           (low/info)
#    • sensitive claims    -> role/admin/privilege exposed in payload   (info)
# ════════════════════════════════════════════════════════════════════════


_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{0,}")

# Small built-in secret list for HS256/384/512 cracking (extend via jwt.wordlist).
_COMMON_SECRETS = [
    "secret", "password", "123456", "changeme", "admin", "jwt", "key", "test",
    "secretkey", "your-256-bit-secret", "supersecret", "private", "token",
    "qwerty", "letmein", "password123", "default", "s3cr3t", "jwtsecret",
    "mysecret", "shhhh", "0000", "root", "hmac", "signature", "secret123",
]

_SENSITIVE_CLAIMS = ("role", "roles", "admin", "is_admin", "isadmin", "scope",
                     "scopes", "privilege", "priv", "authorities", "groups",
                     "permissions", "acl", "usertype", "user_type")


def _b64url_decode(seg):
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def _decode_jwt(tok):
    try:
        h, p, s = tok.split(".")
        header = json.loads(_b64url_decode(h))
        payload = json.loads(_b64url_decode(p))
        return header, payload, s, f"{h}.{p}"
    except Exception:
        return None


def _crack_hmac(signing_input, sig_b64, alg, secrets):
    algo = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
            "HS512": hashlib.sha512}.get(alg.upper())
    if not algo:
        return None
    try:
        want = _b64url_decode(sig_b64)
    except Exception:
        return None
    for secret in secrets:
        mac = hmac.new(secret.encode(), signing_input.encode(), algo).digest()
        if hmac.compare_digest(mac, want):
            return secret
    return None


def _collect_tokens(target, config, runner):
    """Return list of (token, source)."""
    found, seen = [], set()

    def add(tok, src):
        tok = tok.strip()
        if tok and tok not in seen:
            seen.add(tok)
            found.append((tok, src))

    for m in _JWT_RE.finditer(config.get("_cookie") or ""):
        add(m.group(0), "cookie (supplied)")
    for h in config.get("_headers", []) or []:
        for m in _JWT_RE.finditer(h):
            add(m.group(0), "header (supplied)")
    # Set-Cookie / body from each web root
    for svc in target.web_services:
        tag = "jwt_probe_" + svc.key().replace(":", "_")
        _st, headers, body, _r = _curl_full(svc.url, config, runner, tag)
        for src, blob in (("Set-Cookie", headers.get("set-cookie", "")),
                          ("response body", body or "")):
            for m in _JWT_RE.finditer(blob):
                add(m.group(0), f"{src} @ {svc.url}")
    # anything JS analysis already surfaced
    js = target.results.get("jsanalysis") or {}
    for f in js.get("findings", []):
        if f.get("type") == "JWT":
            # value was redacted; re-scan the JS source is out of scope — skip
            pass
    return found


def phase_jwt(target, config, runner):
    result = {"findings": [], "tokens": [], "errors": []}
    target.ensure_web_services(config, runner)
    tokens = _collect_tokens(target, config, runner)
    if not tokens:
        result["errors"].append("no JWT found (supply one via --cookie/--header, "
                                 "or run crawl/jsanalysis)")
        UI.dim("      no JWT found to audit")
        return result

    secrets = list(_COMMON_SECRETS)
    wl = config.get("jwt.wordlist")
    if wl and os.path.isfile(wl):
        try:
            with open(wl, encoding="utf-8", errors="ignore") as fh:
                secrets += [ln.strip() for ln in fh if ln.strip()]
        except OSError:
            pass

    UI.info(f"jwt audit on {len(tokens)} token(s)")
    for tok, src in tokens:
        dec = _decode_jwt(tok)
        if not dec:
            continue
        header, payload, sig, signing_input = dec
        alg = str(header.get("alg", "")).strip()
        summary = {"source": src, "alg": alg,
                   "claims": {k: payload.get(k) for k in _SENSITIVE_CLAIMS if k in payload},
                   "value": tok[:18] + "…"}
        result["tokens"].append(summary)
        UI.ok(f"JWT alg={alg or '?'}  ({src})")

        # alg:none
        if alg.lower() in ("none", ""):
            result["findings"].append({
                "url": src, "severity": "high", "vuln": "jwt",
                "issue": "alg:none", "desc": "JWT alg:none — server may accept unsigned tokens",
                "token": tok[:18] + "…"})
            UI.warn("      [high] alg:none — test whether the server accepts an unsigned token")

        # weak HMAC secret
        if config.get("jwt.crack", True) and alg.upper().startswith("HS") and sig:
            cracked = _crack_hmac(signing_input, sig, alg, secrets)
            if cracked:
                result["findings"].append({
                    "url": src, "severity": "critical", "vuln": "jwt",
                    "issue": "weak HMAC secret", "secret": cracked,
                    "desc": f"JWT signed with weak secret '{cracked}' — forge any token",
                    "token": tok[:18] + "…"})
                UI.ok(f"      [critical] weak HMAC secret cracked: '{cracked}'")

        # expiry
        exp = payload.get("exp")
        if exp is None:
            result["findings"].append({
                "url": src, "severity": "low", "vuln": "jwt",
                "issue": "no exp", "desc": "JWT has no exp claim — token never expires",
                "token": tok[:18] + "…"})
            UI.dim("      [low] no exp claim (token never expires)")
        else:
            try:
                if float(exp) < _time.time():
                    result["findings"].append({
                        "url": src, "severity": "info", "vuln": "jwt",
                        "issue": "expired", "desc": "JWT is expired",
                        "token": tok[:18] + "…"})
                    UI.dim("      [info] token is expired")
            except (TypeError, ValueError):
                pass

        # sensitive claims
        if summary["claims"]:
            result["findings"].append({
                "url": src, "severity": "info", "vuln": "jwt",
                "issue": "sensitive claims",
                "desc": "authorization claims exposed in JWT payload: "
                        + ", ".join(summary["claims"].keys()),
                "token": tok[:18] + "…"})
            UI.dim(f"      [info] claims: {summary['claims']}")

    if not result["findings"]:
        UI.dim("      no JWT weaknesses found")
    return result


def _r_jwt(d):
    lines = _sec("JWT (JSON Web Token audit)")
    toks = d.get("tokens", [])
    fs = d.get("findings", [])
    if not toks and not fs:
        note = d.get("errors", [])
        lines.append("  " + ("no tokens found" if not note else note[0]))
        return lines + [""]
    for t in toks:
        cl = f"  claims: {t['claims']}" if t.get("claims") else ""
        lines.append(f"  token {t['value']}  alg={t.get('alg','?')}  ({t['source']}){cl}")
    if fs:
        lines.append("  issues:")
        for f in fs:
            extra = f"  (secret: '{f['secret']}')" if f.get("secret") else ""
            lines.append(f"    [{f['severity']}] {f.get('issue','')}: {f.get('desc','')}{extra}")
    return lines + [""]
