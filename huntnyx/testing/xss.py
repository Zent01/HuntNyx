from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


def _dalfox_sub():
    try:
        h = subprocess.run(["dalfox", "--help"], capture_output=True, text=True, timeout=15)
        txt = (h.stdout or "") + (h.stderr or "")
        if re.search(r"\bscan\b", txt):
            return "scan"
    except Exception:
        pass
    return "url"


def _dalfox_findings(raw):
    raw = (raw or "").strip()
    if not raw:
        return []
    out = []
    try:
        j = json.loads(raw)
        if isinstance(j, dict):
            j = j.get("pocs") or j.get("results") or []
        for e in j if isinstance(j, list) else []:
            if not isinstance(e, dict):
                continue
            if not (e.get("param") or e.get("data") or e.get("evidence")):
                continue
            etype = str(e.get("type", "")).upper()
            verified = etype == "V"          # dalfox: V=verified, R=reflected, G=grep
            out.append({
                "type": etype,
                "verified": verified,
                "param": e.get("param", ""),
                "inject": e.get("inject_type", e.get("poc_type", "")),
                "severity": (e.get("severity") or "").title() or ("High" if verified else "Medium"),
                "cwe": e.get("cwe", ""),
                "poc": e.get("data", e.get("evidence", "")),
            })
        if out:
            return out
    except Exception:
        pass
    ansi = re.compile(r"\x1b\[[0-9;]*m")
    for line in raw.splitlines():
        s = ansi.sub("", line).strip()
        if "[POC]" not in s and not s.startswith(("[V]", "[R]", "[G]")):
            continue
        mtype = re.search(r"\[(V|R|G)\]", s)
        mmeth = re.search(r"\[(GET|POST)\]", s)
        minj = re.search(r"\[(inHTML|inJS|inATTR|inURL|none|toBlind|toGrepping)[^\]]*\]", s, re.I)
        murl = re.search(r"https?://\S+", s)
        url = murl.group(0) if murl else ""
        param = ""
        if url:
            try:
                qs = parse_qs(urlsplit(url).query, keep_blank_values=True)
                param = next((k for k, v in qs.items()
                              if any(x in (v[0] if v else "").lower()
                                     for x in ("<", "alert", "svg", "onload", "%3c", "dlx"))), "")
                if not param and qs:
                    param = list(qs.keys())[0]
            except Exception:
                param = ""
        etype = mtype.group(1) if mtype else ""
        verified = etype == "V"          # only V is a triggered/verified XSS
        out.append({
            "type": etype or "V",
            "verified": verified,
            "param": param,
            "inject": minj.group(1) if minj else "",
            "method": mmeth.group(1) if mmeth else "GET",
            "severity": "High" if verified else "Medium",
            "cwe": "CWE-79",
            "poc": url or s,
        })
    return out


def phase_xss(target, config, runner):
    result = {"findings": [], "errors": [],
              "note": "XSS scanning by dalfox (GET params + POST forms)"}
    if not shutil.which("dalfox"):
        result["errors"].append("dalfox not installed")
        return result
    target.ensure_web_services(config, runner)
    endpoints = _active_targets(target)
    forms = _post_forms(target)
    direct = []
    seen_direct = set()
    for u in [s.url for s in target.web_services] + list(getattr(target, "seed_urls", [])):
        key = urlsplit(u).path + "?" + urlsplit(u).query
        if u and key not in seen_direct:
            seen_direct.add(key)
            direct.append(u)
    if not endpoints and not forms and not direct:
        result["errors"].append("no web services / endpoints to test")
        UI.warn("xss: nothing to test")
        return result

    timeout = config.get("timeouts.dalfox", 600)
    max_ep = config.get("active.max_endpoints", 60)
    extra = config.get("dalfox.extra_args", []) or []
    sub = _dalfox_sub()
    hdr = []
    for h in auth_header_pairs(config):
        hdr += ["-H", h]

    def run_dalfox(url, tag, data=None):
        cmd = ["dalfox", sub, url, "--format", "json"]
        if data:
            cmd += ["--data", data]
        cmd += hdr + extra
        res = runner.run(cmd, log_name=f"dalfox_{tag}", timeout=timeout, heartbeat=True)
        return _dalfox_findings((res.stdout or "") + "\n" + (res.stderr or ""))

    idx = 0
    get_urls, seen_g = [], set()

    def add_get(url, key):
        nonlocal idx
        if key in seen_g:
            return
        seen_g.add(key)
        get_urls.append(url)

    for pe in endpoints[:max_ep]:
        sp = urlsplit(pe["url"])
        add_get(_build_url(pe["url"], {p: "1" for p in pe["params"]}),
                (sp.path, tuple(sorted(pe["params"]))))
    for u in direct[:max_ep]:
        sp = urlsplit(u)
        keys = tuple(sorted(parse_qs(sp.query, keep_blank_values=True).keys()))
        add_get(u, (sp.path, keys))

    for u in get_urls[:max_ep]:
        idx += 1
        UI.info(f"dalfox {UI.c(u, UI.WHITE)}")
        for f in run_dalfox(u, f"get_{idx}"):
            f["method"] = "GET"
            f["url"] = u
            result["findings"].append(f)
            if f.get("verified"):
                UI.ok(f"XSS [CONFIRMED/{f['severity']}] {u} [{f['param']}] {f['inject']}")
            else:
                UI.warn(f"XSS [review:{f.get('type','?')}] {u} [{f['param']}] {f['inject']} — manual verification")

    for fm in forms[:max_ep]:
        idx += 1
        data = "&".join(f"{i}=1" for i in fm["inputs"])
        UI.info(f"dalfox POST {UI.c(fm['action'], UI.WHITE)}")
        for f in run_dalfox(fm["action"], f"post_{idx}", data=data):
            f["method"] = "POST"
            f["url"] = fm["action"]
            result["findings"].append(f)
            if f.get("verified"):
                UI.ok(f"XSS [CONFIRMED/{f['severity']}] {fm['action']} [{f['param']}] {f['inject']}")
            else:
                UI.warn(f"XSS [review:{f.get('type','?')}] {fm['action']} [{f['param']}] {f['inject']} — manual verification")

    uniq, seen_f = [], set()
    for f in result["findings"]:
        k = (f.get("method"), urlsplit(f.get("url", "")).path, f.get("param"), f.get("inject"))
        if k not in seen_f:
            seen_f.add(k)
            uniq.append(f)
    result["findings"] = uniq
    if not result["findings"]:
        UI.dim("      dalfox found no XSS")
    return result


def _r_xss(d):
    lines = _sec("XSS (dalfox)")
    fs = d.get("findings", [])
    if not fs:
        note = d.get("errors", [])
        lines.append("  " + ("no XSS found" if not note else note[0]))
        return lines + [""]
    confirmed = [f for f in fs if f.get("verified")]
    review = [f for f in fs if not f.get("verified")]

    def _row(f, tag):
        lines.append(f"  {tag} [{f.get('severity','?')}] {f.get('method','GET')} {f.get('url','')} "
                     f"[{f.get('param','')}]  {f.get('inject','')} {('('+f['cwe']+')') if f.get('cwe') else ''}")
        if f.get("poc"):
            lines.append(f"      PoC: {f['poc']}")

    for f in confirmed:
        _row(f, "[CONFIRMED]")
    for f in review:
        _row(f, "[review — reflected/grep only, manual verification]")
    return lines + [""]
