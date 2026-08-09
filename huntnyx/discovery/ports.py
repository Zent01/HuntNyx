from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


WEB_HINTS = ("http", "https", "http-alt", "http-proxy", "https-alt", "ssl/http", "http-mgmt")


COMMON_WEB_PORTS = {80, 443, 8080, 8000, 8443, 8888, 8081, 8008, 3000, 5000, 9090}


def _parse_nmap(xml_path):
    out = []
    try:
        tree = ET.parse(xml_path)
    except Exception:
        return out
    for host in tree.getroot().findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue
        for p in ports.findall("port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            out.append({
                "port": int(p.get("portid")), "proto": p.get("protocol"),
                "service": (svc.get("name") if svc is not None else "") or "",
                "product": (svc.get("product") if svc is not None else "") or "",
                "version": (svc.get("version") if svc is not None else "") or "",
                "tunnel": (svc.get("tunnel") if svc is not None else "") or "",
            })
    return out


def _is_web(entry):
    name, tunnel, port = entry["service"].lower(), entry["tunnel"].lower(), entry["port"]
    if any(h in name for h in WEB_HINTS) or port in COMMON_WEB_PORTS:
        scheme = "https" if ("https" in name or "ssl" in name or tunnel == "ssl"
                             or port in (443, 8443, 4443)) else "http"
        return True, scheme
    return False, ""


def phase_ports(target, config, runner):
    result = {"open_ports": [], "web_services": [], "errors": []}
    disc_xml = str(target.artifacts_dir / "nmap_discovery.xml")
    full = config.get("nmap.full_scan", False)
    top = config.get("nmap.top_ports", 1000)
    extra = config.get("nmap.extra_args", []) or []
    timeout = config.get("timeouts.nmap", 1800)

    cmd = ["nmap", "-Pn", "-T4", "-oX", disc_xml]
    cmd += ["-p-"] if full else ["--top-ports", str(top)]
    cmd += extra + [target.name]
    UI.info("discovery scan")
    r1 = runner.run(cmd, log_name="nmap_discovery", timeout=timeout, heartbeat=True)
    if r1.error:
        result["errors"].append(r1.error)
        return result
    open_ports = _parse_nmap(disc_xml)
    if not open_ports:
        UI.warn("no open ports found")
        return result
    port_list = ",".join(str(e["port"]) for e in open_ports)
    UI.ok(f"open: {port_list}")

    svc_xml = str(target.artifacts_dir / "nmap_service.xml")
    scmd = ["nmap", "-Pn", "-sV", "-T4", "-p", port_list, "-oX", svc_xml]
    if config.get("nmap.scripts", True):
        scmd.insert(3, "-sC")
    scmd += extra + [target.name]
    UI.info("service/script scan")
    r2 = runner.run(scmd, log_name="nmap_service", timeout=timeout, heartbeat=True)
    detailed = _parse_nmap(svc_xml) if not r2.error else open_ports

    result["open_ports"] = detailed
    for e in detailed:
        ver = " ".join(x for x in (e.get("product"), e.get("version")) if x) or e.get("service", "")
        UI.ok(f"{e['port']}/{e.get('proto', 'tcp')}  {ver}".rstrip())
    for entry in detailed:
        is_web, scheme = _is_web(entry)
        if is_web:
            target.add_web_service(entry["port"], scheme)
            result["web_services"].append({"port": entry["port"], "scheme": scheme})
    if result["web_services"]:
        UI.ok("web services: " + ", ".join(f"{w['scheme']}:{w['port']}" for w in result["web_services"]))
    else:
        UI.warn("no web services detected")
    return result


def _r_ports(d):
    lines = _sec("PORTS & SERVICES")
    ports = d.get("open_ports", [])
    if not ports:
        return lines + ["  none found", ""]
    for p in ports:
        pv = " ".join(x for x in (p.get("product"), p.get("version")) if x)
        lines.append(f"  {p['port']:>5}/{p.get('proto','')}  {p.get('service',''):<12} {pv}")
    return lines + [""]
