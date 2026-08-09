from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


def _resolve_host(host):
    import socket
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def phase_subdomains(target, config, runner):
    """Passive subdomain discovery via subfinder. Optional: skips cleanly if
    subfinder isn't installed or the target has no domain. Resolvable subdomains
    are queued as web services so later phases can enumerate them (capped).
    Note: subfinder uses public/passive sources, so internal lab domains like
    '*.thm' typically won't resolve — use --vhost (ffuf) for those."""
    result = {"subdomains": [], "errors": []}
    if not shutil.which("subfinder"):
        result["errors"].append("subfinder not installed")
        return result
    domain = config.get("_domain")
    if not domain:
        host = target.name
        if host and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            domain = host
    if not domain:
        result["errors"].append("subdomains skipped: no domain (target is an IP; pass --domain)")
        UI.warn("subdomains skipped (needs a domain — use --domain)")
        return result

    out_file = str(target.artifacts_dir / "subfinder.txt")
    cmd = ["subfinder", "-d", domain, "-silent", "-o", out_file]
    cmd += config.get("subfinder.extra_args", []) or []
    UI.info(f"subfinder {UI.c(domain, UI.WHITE)}  {UI.c('(passive subdomains)', UI.GREY)}")
    res = runner.run(cmd, log_name="subfinder", timeout=config.get("timeouts.subfinder", 600),
                     heartbeat=True)

    text = ""
    try:
        text = Path(out_file).read_text(encoding="utf-8")
    except Exception:
        pass
    if not text.strip():
        text = res.stdout
    subs = []
    for line in text.splitlines():
        s = line.strip().lower()
        if s and "." in s and re.match(r"^[a-z0-9._-]+$", s):
            subs.append(s)
    subs = sorted(set(subs))
    UI.ok(f"{len(subs)} subdomain(s)")

    max_add = int(config.get("subfinder.max_add", 25) or 25)
    queued = 0
    for sub in subs:
        ip = _resolve_host(sub)
        result["subdomains"].append({"host": sub, "ip": ip})
        UI.dim(f"      {sub}" + (f"  -> {ip}" if ip else "  (no DNS)"))
        if ip and queued < max_add:
            before = len(target.web_services)
            target.add_web_service(80, "http", host=sub)
            target.add_web_service(443, "https", host=sub)
            if len(target.web_services) > before:
                queued += 1
    if queued:
        UI.dim(f"      +{queued} resolvable subdomain(s) queued for enumeration")
    elif subs:
        UI.dim("      none resolve publicly (expected for internal/lab domains — use --vhost)")
    return result


def _r_subdomains(d):
    lines = _sec("SUBDOMAINS (subfinder)")
    subs = d.get("subdomains", [])
    if not subs:
        note = d.get("errors", [])
        return lines + ["  " + ("none found" if not note else note[0]), ""]
    for s in subs:
        lines.append(f"  {s['host']}" + (f"  -> {s['ip']}" if s.get("ip") else "  (no DNS)"))
    return lines + [""]
