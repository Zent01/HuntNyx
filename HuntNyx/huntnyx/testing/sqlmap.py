from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


def _parse_sqlmap(out):
    low = out.lower()
    if "identified the following injection point" not in low and \
       "the following injection point" not in low and "is vulnerable" not in low:
        return []
    details = []
    for line in out.splitlines():
        s = line.strip()
        if s.startswith(("Parameter:", "Type:", "Title:", "back-end DBMS:")):
            details.append(s)
    return details or ["injectable (see raw log)"]


def phase_sqlmap(target, config, runner):
    result = {"runs": [], "injectable": [], "errors": []}
    if not shutil.which("sqlmap"):
        result["errors"].append("sqlmap not installed")
        return result
    target.ensure_web_services(config, runner)
    endpoints = _active_targets(target)
    forms = _post_forms(target)
    request_file = config.get("_request_file")
    if not endpoints and not forms and not request_file:
        result["errors"].append("no targets for sqlmap (run content/crawl/arjun first)")
        UI.warn("sqlmap: nothing to test")
        return result

    timeout = config.get("timeouts.sqlmap", 1800)
    base = ["sqlmap", "--batch", "-v", "0",
            "--level", str(config.get("sqlmap.level", 2)),
            "--risk", str(config.get("sqlmap.risk", 2)), "--flush-session"]
    extra = config.get("sqlmap.extra_args", []) or []
    if config.get("_cookie"):
        base += ["--cookie", config.get("_cookie")]
    for h in config.get("_headers", []) or []:
        base += ["-H", h]
    base += extra

    targets = []
    if request_file:
        targets.append({"desc": f"request-file ({os.path.basename(request_file)})",
                        "cmd": ["sqlmap", "-r", request_file, "--batch", "-v", "0",
                                "--level", str(config.get("sqlmap.level", 2)),
                                "--risk", str(config.get("sqlmap.risk", 2)),
                                "--flush-session"] + extra})
    for pe in endpoints:
        params = ",".join(pe["params"])
        targets.append({"desc": f"GET {pe['url']} [{params}]",
                        "cmd": base + ["-u", pe["url"], "-p", params]})
    for fm in forms:
        data = "&".join(f"{i}=1" for i in fm["inputs"])
        params = ",".join(fm["inputs"])
        targets.append({"desc": f"POST {fm['action']} [{params}]",
                        "cmd": base + ["-u", fm["action"], "--data", data, "-p", params]})

    max_t = config.get("sqlmap.max_targets", 15)
    for i, t in enumerate(targets[:max_t]):
        UI.info(f"sqlmap {UI.c(t['desc'], UI.WHITE)}")
        res = runner.run(t["cmd"], log_name=f"sqlmap_{i}", timeout=timeout, heartbeat=True)
        inj = _parse_sqlmap((res.stdout or "") + "\n" + (res.stderr or ""))
        result["runs"].append({"target": t["desc"], "injectable": bool(inj)})
        if inj:
            result["injectable"].append({"target": t["desc"], "details": inj})
            UI.ok(f"INJECTABLE: {t['desc']}")
            for d in inj:
                UI.dim(f"      {d}")
        else:
            UI.dim("      no injection confirmed")
    if not result["injectable"]:
        UI.dim(f"      sqlmap ran {len(result['runs'])} target(s), none confirmed")
    return result


def _r_sqlmap(d):
    lines = _sec("SQLMAP (CONFIRMED)")
    runs = d.get("runs", [])
    inj = d.get("injectable", [])
    if not runs:
        note = d.get("errors", [])
        lines.append("  " + ("no targets" if not note else note[0]))
        return lines + [""]
    if not inj:
        lines.append(f"  ran {len(runs)} target(s) — no injection confirmed")
        return lines + [""]
    for i in inj:
        lines.append(f"  {i['target']}")
        for det in i["details"]:
            lines.append(f"      {det}")
    lines.append("  -> to extract data: re-run that sqlmap cmd with --dump (authorized lab only)")
    return lines + [""]
