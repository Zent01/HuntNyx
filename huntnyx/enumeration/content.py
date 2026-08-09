from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


GOBUSTER_RE = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)(?:\s*\[Size:\s*(\d+)\])?")


def _content_wordlist(config):
    wl = config.get("wordlists.content")
    if not wl or not os.path.isfile(wl):
        UI.warn(f"content wordlist not found: {wl}")
        return None
    return wl


def _gobuster_content(svc, wl, config, runner, tag):
    out_file = str(target_artifacts(config) / f"gobuster_{tag}.txt")
    exts = ",".join(e.lstrip(".") for e in config.get("extensions", []))

    cmd = ["gobuster", "dir", "-u", svc.url, "-w", wl,
           "-t", str(config.get("threads", 40)),
           "--timeout", str(config.get("content.req_timeout", "10s")),
           "-q", "-o", out_file]
    if exts:
        cmd += ["-x", exts]
    if svc.scheme == "https":
        cmd += ["-k"]
    if config.get("content.status_codes"):
        cmd += ["-s", str(config.get("content.status_codes")), "-b", ""]
    if config.get("_cookie"):
        cmd += ["-c", config.get("_cookie")]
    for h in config.get("_headers", []) or []:
        cmd += ["-H", h]

    res = runner.run(cmd, log_name=f"gobuster_{tag}",
                     timeout=config.get("timeouts.gobuster", 600), heartbeat=True)

    text = ""
    try:
        text = Path(out_file).read_text(encoding="utf-8")
    except Exception:
        pass
    if not text.strip():
        text = res.stdout

    found, seen = [], set()
    for line in text.splitlines():
        m = GOBUSTER_RE.match(line.strip())
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            found.append({"path": m.group(1), "status": int(m.group(2)),
                          "length": int(m.group(3)) if m.group(3) else None})
    return found


def _ferox_content(svc, wl, config, runner, tag):
    out_json = str(target_artifacts(config) / f"ferox_{tag}.json")
    exts = ",".join(e.lstrip(".") for e in config.get("extensions", []))
    cmd = ["feroxbuster", "-u", svc.url, "-w", wl, "-t", str(config.get("threads", 40)),
           "--json", "-o", out_json, "-q", "--no-state"]
    if exts:
        cmd += ["-x", exts]
    runner.run(cmd, log_name=f"ferox_{tag}", timeout=config.get("timeouts.feroxbuster", 900), heartbeat=True)
    found = []
    try:
        with open(out_json, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                if r.get("type") == "response":
                    found.append({"path": r.get("path", ""), "status": r.get("status"),
                                  "length": r.get("content_length")})
    except Exception:
        pass
    return found


def target_artifacts(config):
    return Path(config.get("_artifacts_dir", "/tmp"))


def phase_content(target, config, runner):
    target.ensure_web_services(config, runner)
    config.set("_artifacts_dir", str(target.artifacts_dir))
    result = {"services": [], "errors": []}
    if not target.web_services:
        result["errors"].append("no web services for content discovery")
        return result
    wl = _content_wordlist(config)
    if not wl:
        result["errors"].append("content wordlist missing")
        return result
    engine = "gobuster" if shutil.which("gobuster") else (
        "feroxbuster" if shutil.which("feroxbuster") else None)
    if not engine:
        result["errors"].append("no content engine (gobuster/feroxbuster)")
        return result
    for svc in target.web_services:
        tag = svc.key().replace(":", "_")
        UI.info(f"content {UI.c(svc.url, UI.WHITE)}  {UI.c('(' + engine + ')', UI.GREY)}")
        found = (_gobuster_content if engine == "gobuster" else _ferox_content)(
            svc, wl, config, runner, tag)
        found.sort(key=lambda x: (x.get("status") or 0, x.get("path") or ""))
        UI.ok(f"{len(found)} paths")
        for f in found[:40]:
            length = f"{f['length']}b" if f.get("length") is not None else "-"
            UI.dim(f"      {f['status']}  {f['path']}  ({length})")
        result["services"].append({"url": svc.url, "engine": engine, "found": found})
    return result


def _r_content(d):
    lines = _sec("CONTENT DISCOVERY")
    for s in d.get("services", []):
        found = s.get("found", [])
        lines.append(f"  {s['url']}  ({len(found)} paths, {s.get('engine','')})")
        if not found:
            lines += ["    nothing found", ""]
            continue
        for f in found:
            length = f"{f['length']}b" if f.get("length") is not None else "-"
            lines.append(f"    [{f.get('status','')}] {f.get('path','')}  ({length})")
        lines.append("")
    return lines
