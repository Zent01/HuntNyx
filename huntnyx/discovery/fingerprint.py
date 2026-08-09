from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


def _headers(url, config, runner, tag):
    timeout = config.get("timeouts.curl", 15)
    res = runner.run(["curl", "-s", "-D", "-", "-o", "/dev/null", "-k",
                      "--max-time", str(timeout), *auth_curl(config), url],
                     log_name=f"headers_{tag}", timeout=timeout + 5)
    headers = {}
    for line in res.stdout.splitlines():
        if ":" in line and not line.startswith("HTTP/"):
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    m = re.search(r"HTTP/\S+\s+(\d{3})", res.stdout)
    interesting = {k: headers[k] for k in
                   ("server", "x-powered-by", "content-type", "location",
                    "set-cookie", "x-generator", "www-authenticate") if k in headers}
    return {"status": m.group(1) if m else "", "headers": interesting}


def _is_ipaddr(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _tls_name(seq):
    if not seq:
        return ""
    return ", ".join(f"{k}={v}" for rdn in seq for k, v in rdn)


def _der_sans(der):
    """Best-effort dNSName extraction from a DER cert (no openssl / crypto lib).
    Locates the subjectAltName extension (OID 2.5.29.17) and reads the
    context-[2] dNSName entries. Handles short-form lengths, which cover
    essentially all real hostnames."""
    if not der:
        return []
    oid = b"\x06\x03\x55\x1d\x11"
    start = der.find(oid)
    if start == -1:
        return []
    region = der[start + len(oid): start + len(oid) + 8192]
    names, k = [], 0
    while k < len(region) - 2:
        if region[k] == 0x82:
            ln = region[k + 1]
            if 0 < ln < 0x80 and k + 2 + ln <= len(region):
                cand = region[k + 2: k + 2 + ln]
                try:
                    s = cand.decode("ascii")
                except Exception:
                    s = ""
                if s and "." in s and re.match(r"^[A-Za-z0-9._*-]+$", s):
                    names.append(s)
                    k += 2 + ln
                    continue
        k += 1
    return sorted(set(names))


def _tls(host, port, config, runner, tag):
    """TLS certificate details via the stdlib ssl module. Tries a verifying
    handshake first (subject / issuer / SANs); on failure — e.g. self-signed
    lab certs — falls back to an unverified handshake and scrapes SANs from
    the DER."""
    import socket, ssl
    timeout = config.get("timeouts.tls", 15)
    sni = None if _is_ipaddr(host) else host
    if sni:
        try:
            vctx = ssl.create_default_context()
            with socket.create_connection((host, int(port)), timeout=timeout) as sock:
                with vctx.wrap_socket(sock, server_hostname=sni) as ss:
                    cert = ss.getpeercert() or {}
            sans = sorted({v for typ, v in cert.get("subjectAltName", ()) if typ == "DNS"})
            subj, iss = _tls_name(cert.get("subject")), _tls_name(cert.get("issuer"))
            raw = "\n".join(x for x in (f"subject: {subj}" if subj else "",
                                        f"issuer: {iss}" if iss else "") if x)
            return {"raw": raw or "(verified)", "sans": sans, "verified": True}
        except Exception:
            pass
    try:
        uctx = ssl._create_unverified_context()
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            with uctx.wrap_socket(sock, server_hostname=sni) as ss:
                der = ss.getpeercert(binary_form=True)
                version = ss.version() or ""
                cipher = (ss.cipher() or ("", "", ""))[0]
    except Exception:
        return None
    return {"raw": f"tls: {version}  cipher: {cipher}  (untrusted cert)",
            "sans": _der_sans(der), "verified": False}


def phase_fingerprint(target, config, runner):
    target.ensure_web_services(config, runner)
    result = {"services": [], "errors": []}
    if not target.web_services:
        result["errors"].append("no web services to fingerprint")
        return result
    for svc in target.web_services:
        tag = svc.key().replace(":", "_")
        UI.info(f"fingerprint {UI.c(svc.url, UI.WHITE)}")
        http = _headers(svc.url, config, runner, tag)
        if not http.get("status") and not http.get("headers"):
            UI.warn(f"fingerprint {svc.url}: no response (curl failed / target unreachable)")
            result["errors"].append(f"no response from {svc.url}")
            continue
        entry = {"url": svc.url, "http": http}
        if svc.scheme == "https":
            entry["tls"] = _tls(svc.host, svc.port, config, runner, tag)
            sans = (entry["tls"] or {}).get("sans") if entry.get("tls") else None
            if sans:
                UI.ok("TLS SANs: " + ", ".join(sans))
        srv = entry["http"]["headers"].get("server")
        if srv:
            UI.ok(f"Server: {srv}")
        result["services"].append(entry)
    return result


def _r_fingerprint(d):
    lines = _sec("WEB FINGERPRINT")
    essential = ("server", "x-powered-by", "content-type", "www-authenticate", "location")
    for s in d.get("services", []):
        lines.append(f"  {s['url']}")
        http = s.get("http", {})
        if http.get("status"):
            lines.append(f"    status: {http['status']}")
        headers = http.get("headers") or {}
        seen = set()
        for k in essential:
            v = headers.get(k)
            if v and k not in seen:
                seen.add(k)
                lines.append(f"    {k}: {v}")
        sc = headers.get("set-cookie")
        if sc:
            primary = sc.split(",")[0].split(";")[0].strip()
            if primary:
                lines.append(f"    set-cookie: {primary}")
        tls = s.get("tls")
        if tls and tls.get("sans"):
            lines.append(f"    TLS SANs: {', '.join(tls['sans'])}")
        lines.append("")
    return lines
