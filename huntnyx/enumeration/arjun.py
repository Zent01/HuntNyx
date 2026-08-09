from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


def _arjun_target_urls(target, config):
    urls = []
    seen = set()

    def add(u):
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    for svc in target.web_services:
        add(svc.url)
    for su in getattr(target, "seed_urls", []):
        add(su)
    content = target.results.get("content") or {}
    for e in content.get("services", []):
        base = e.get("url", "")
        for f in e.get("found", []):
            if (f.get("status") or 0) in (200, 301, 302, 401, 403):
                add(base.rstrip("/") + "/" + (f.get("path") or "").lstrip("/"))
    crawl = target.results.get("crawl") or {}
    for pe in crawl.get("params", []):
        add(pe.get("url"))
    return urls[: config.get("arjun.max_urls", 25)]


def phase_arjun(target, config, runner):
    result = {"discovered": [], "errors": []}
    if not shutil.which("arjun"):
        result["errors"].append("arjun not installed")
        return result
    target.ensure_web_services(config, runner)
    urls = _arjun_target_urls(target, config)
    if not urls:
        result["errors"].append("no URLs for arjun (run content/crawl first)")
        UI.warn("arjun: nothing to probe")
        return result

    list_file = target.artifacts_dir / "arjun_urls.txt"
    list_file.write_text("\n".join(urls) + "\n")
    out_file = str(target.artifacts_dir / "arjun.json")

    cmd = ["arjun", "-i", str(list_file), "-oJ", out_file,
           "-T", str(config.get("arjun.req_timeout", 10))]
    if config.get("arjun.stable", True):
        cmd += ["--stable"]
    if config.get("arjun.wordlist"):
        cmd += ["-w", config.get("arjun.wordlist")]
    pairs = auth_header_pairs(config)
    if pairs:
        cmd += ["--headers", "\n".join(pairs)]
    cmd += config.get("arjun.extra_args", []) or []

    UI.info(f"arjun on {len(urls)} URL(s)  {UI.c('(hidden-param discovery)', UI.GREY)}")
    res = runner.run(cmd, log_name="arjun", timeout=config.get("timeouts.arjun", 900),
                     heartbeat=True)

    data = {}
    try:
        data = json.loads(Path(out_file).read_text(encoding="utf-8"))
    except Exception:
        data = {}

    added = 0
    for url, val in (data.items() if isinstance(data, dict) else []):
        if isinstance(val, dict):
            found = val.get("params", []) or []
        elif isinstance(val, list):
            found = val
        else:
            found = []
        if not found:
            continue
        result["discovered"].append({"url": url, "params": found})
        UI.ok(f"arjun: {url}  ->  {', '.join(found)}")
        sp = urlsplit(url)
        clean = f"{sp.scheme}://{sp.netloc}{sp.path}"
        sig = (sp.path, tuple(sorted(found)))
        existing = {(urlsplit(pe['url']).path, tuple(sorted(pe['params'])))
                    for pe in target.param_endpoints}
        if sig not in existing:
            target.param_endpoints.append({"url": clean, "params": list(found)})
            added += 1

    if not result["discovered"]:
        UI.dim("      no hidden params found")
    elif added:
        UI.dim(f"      +{added} endpoint(s) queued for active checks")
    return result


def _r_arjun(d):
    lines = _sec("ARJUN (HIDDEN PARAMS)")
    disc = d.get("discovered", [])
    if not disc:
        note = d.get("errors", [])
        lines.append("  " + ("no hidden params found" if not note else note[0]))
        return lines + [""]
    for e in disc:
        lines.append(f"  {e['url']}  ->  {', '.join(e['params'])}")
    lines.append("  (queued into the active checks)")
    return lines + [""]
