from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


def _vhost_wordlist(config):
    wl = config.get("wordlists.vhost")
    if wl and os.path.isfile(wl):
        return wl
    UI.warn(f"vhost wordlist not found: {wl or '(unset)'}")
    return None


def phase_vhost(target, config, runner):
    result = {"services": [], "errors": []}
    domain = config.get("_domain")
    if not domain:
        host = target.name
        if host and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            domain = host
    if not domain:
        result["errors"].append("vhost skipped: no domain (target is an IP; pass --domain)")
        UI.warn("vhost skipped (needs a hostname/domain — use --domain)")
        return result
    target.ensure_web_services(config, runner)
    if not target.web_services:
        result["errors"].append("no web services for vhost fuzzing")
        return result
    wl = _vhost_wordlist(config)
    if not wl:
        result["errors"].append("vhost wordlist missing")
        return result
    if not shutil.which("ffuf"):
        result["errors"].append("vhost fuzzing needs ffuf")
        return result
    new_vhosts = []
    for svc in list(target.web_services):
        tag = svc.key().replace(":", "_")
        UI.info(f"vhost {UI.c(svc.url, UI.WHITE)}  {UI.c('domain=' + domain, UI.GREY)}")
        out_json = str(target.artifacts_dir / f"ffuf_vhost_{tag}.json")
        cmd = ["ffuf", "-u", svc.url, "-H", f"Host: FUZZ.{domain}", "-w", wl,
               "-t", str(config.get("threads", 40)), "-of", "json", "-o", out_json,
               "-s", "-ac"]
        if config.get("vhost.filter_codes"):
            cmd += ["-fc", str(config.get("vhost.filter_codes"))]
        if config.get("vhost.filter_size"):
            cmd += ["-fs", str(config.get("vhost.filter_size"))]
        for h in auth_header_pairs(config):
            cmd += ["-H", h]
        cmd += config.get("vhost.extra_args", []) or []
        runner.run(cmd, log_name=f"ffuf_vhost_{tag}", timeout=config.get("timeouts.ffuf", 900),
                   heartbeat=True)
        found = []
        try:
            with open(out_json, encoding="utf-8") as fh:
                for r in json.load(fh).get("results", []):
                    sub = r.get("input", {}).get("FUZZ", "")
                    found.append({"vhost": f"{sub}.{domain}", "status": r.get("status"),
                                  "length": r.get("length"), "port": svc.port, "scheme": svc.scheme})
        except Exception:
            pass
        for f in found:
            UI.ok(f"{f['vhost']}  ({f['status']}, {f['length']}b)")
        if not found:
            UI.dim("      no vhosts (try a bigger wordlist / add found ones to /etc/hosts)")
        new_vhosts += found
        result["services"].append({"url": svc.url, "domain": domain, "found": found})

    added = 0
    for f in new_vhosts:
        before = len(target.web_services)
        target.add_web_service(f["port"], f["scheme"], host=f["vhost"])
        added += len(target.web_services) > before
    if added:
        UI.dim(f"      +{added} vhost(s) queued for enumeration/testing")
    _offer_add_hosts(new_vhosts, domain, config, result)
    return result


def _offer_add_hosts(new_vhosts, domain, config, result):
    if not new_vhosts:
        return
    import socket
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        UI.warn("could not resolve base IP — add vhosts to /etc/hosts manually")
        return
    try:
        existing = open("/etc/hosts", encoding="utf-8", errors="ignore").read()
    except Exception:
        existing = ""
    pending = [f["vhost"] for f in new_vhosts if f["vhost"] not in existing]
    if not pending:
        return
    do_add = config.get("_add_hosts")
    if not do_add:
        if config.get("_yes") or not sys.stdin.isatty():
            UI.dim("      tip: re-run with --add-hosts to add these to /etc/hosts and scan them")
            return
        do_add = UI.ask_yes_no(f"Add {len(pending)} vhost(s) to /etc/hosts and scan them now?",
                               default=False)
    if not do_add:
        return
    block = "# HuntNyx vhosts\n" + "".join(f"{ip}\t{h}\n" for h in pending)
    try:
        with open("/etc/hosts", "a", encoding="utf-8") as fh:
            fh.write(block)
        UI.ok(f"added {len(pending)} vhost(s) to /etc/hosts — later phases will scan them")
        result["hosts_added"] = pending
    except PermissionError:
        UI.warn("cannot write /etc/hosts (run with sudo/root). Add manually:")
        for h in pending:
            UI.dim(f"      {ip}\t{h}")
    except Exception as exc:
        UI.warn(f"/etc/hosts write failed: {exc}")


def _r_vhost(d):
    lines = _sec("VIRTUAL HOSTS / SUBDOMAINS")
    any_found = False
    for s in d.get("services", []):
        for f in s.get("found", []):
            any_found = True
            lines.append(f"  {f['vhost']}  ({f.get('status')}, {f.get('length')}b)  -> /etc/hosts")
    if not any_found:
        note = d.get("errors", [])
        lines.append("  " + ("no vhosts found" if not note else note[0]))
    return lines + [""]
