from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


def _fetch(url, headers, timeout):
    ctx = _ssl._create_unverified_context()
    opener = build_opener(HTTPSHandler(context=ctx))
    req = Request(url, headers=headers)
    with opener.open(req, timeout=timeout) as r:
        body = r.read(500_000).decode("utf-8", "replace")
        return r.geturl(), r.headers.get("Content-Type", ""), body


def phase_crawl(target, config, runner):
    result = {"pages": 0, "params": [], "forms": [], "js": [], "errors": []}
    target.ensure_web_services(config, runner)
    if not target.web_services:
        result["errors"].append("no web services to crawl")
        return result

    headers = _crawl_headers(config)
    timeout = config.get("crawl.timeout", 10)
    max_pages = config.get("crawl.max_pages", 40)
    max_depth = config.get("crawl.max_depth", 2)

    seen_pages, seen_params, params, forms, js = set(), set(), [], [], set()

    content = target.results.get("content") or {}
    seeds_by_base = {}
    for entry in content.get("services", []):
        base = entry.get("url", "")
        extra = []
        for f in entry.get("found", []):
            if (f.get("status") or 0) in (200, 301, 302, 401, 403):
                path = (f.get("path") or "").lstrip("/")
                if path:
                    extra.append(base.rstrip("/") + "/" + path)
        if extra:
            seeds_by_base[base] = extra

    for svc in target.web_services:
        host = urlparse(svc.url).netloc
        url_seeds = [su for su in getattr(target, "seed_urls", [])
                     if urlsplit(su).netloc == host]
        seeds = list(dict.fromkeys([svc.url] + url_seeds + seeds_by_base.get(svc.url, [])))
        extra_n = len(seeds) - 1
        note = f"(<= {max_pages} pages" + (f", +{extra_n} seeded" if extra_n else "") + ")"
        UI.info(f"crawl {UI.c(svc.url, UI.WHITE)}  {UI.c(note, UI.GREY)}")
        queue = [(u, 0) for u in seeds]
        for su in seeds:
            ssp = urlsplit(su)
            if not ssp.query:
                continue
            keys = tuple(sorted(parse_qs(ssp.query, keep_blank_values=True).keys()))
            if not keys:
                continue
            sig = (ssp.path, keys)
            if sig not in seen_params:
                seen_params.add(sig)
                params.append({"url": f"{ssp.scheme}://{ssp.netloc}{ssp.path}",
                               "params": list(keys)})
        while queue and len(seen_pages) < max_pages:
            url, depth = queue.pop(0)
            if url in seen_pages or depth > max_depth:
                continue
            seen_pages.add(url)
            try:
                final, ctype, body = _fetch(url, headers, timeout)
            except Exception as exc:
                result["errors"].append(f"{url}: {exc}")
                continue
            if "html" not in ctype.lower():
                continue
            p = _LinkParser()
            try:
                p.feed(body)
            except Exception:
                pass
            for f in p.forms:
                action = urljoin(url, f["action"] or "")
                if f["inputs"]:
                    forms.append({"action": action, "method": f["method"], "inputs": f["inputs"]})
                    if f["method"] == "get":
                        fsp = urlsplit(action)
                        if fsp.netloc == host:
                            fclean = f"{fsp.scheme}://{fsp.netloc}{fsp.path}"
                            fsig = (fsp.path, tuple(sorted(f["inputs"])))
                            if fsig not in seen_params:
                                seen_params.add(fsig)
                                params.append({"url": fclean, "params": list(f["inputs"])})
            for href in p.links:
                nxt = urljoin(url, href)
                sp = urlsplit(nxt)
                if sp.scheme not in ("http", "https") or sp.netloc != host:
                    continue
                clean = f"{sp.scheme}://{sp.netloc}{sp.path}"
                if nxt.endswith(".js") or sp.path.endswith(".js"):
                    js.add(clean)
                if sp.query:
                    keys = tuple(sorted(parse_qs(sp.query, keep_blank_values=True).keys()))
                    sig = (sp.path, keys)
                    if sig not in seen_params:
                        seen_params.add(sig)
                        params.append({"url": clean, "params": list(keys)})
                if clean not in seen_pages and len(seen_pages) + len(queue) < max_pages:
                    queue.append((clean, depth + 1))
            for href in getattr(p, "assets", []):
                nxt = urljoin(url, href)
                sp = urlsplit(nxt)
                if sp.scheme not in ("http", "https") or sp.netloc != host:
                    continue
                clean = f"{sp.scheme}://{sp.netloc}{sp.path}"
                if not sp.query:
                    continue
                keys = tuple(sorted(parse_qs(sp.query, keep_blank_values=True).keys()))
                sig = (sp.path, keys)
                if sig not in seen_params:
                    seen_params.add(sig)
                    params.append({"url": clean, "params": list(keys)})

    result["pages"] = len(seen_pages)
    result["params"] = params
    result["forms"] = forms
    result["js"] = sorted(js)
    result["urls"] = sorted({
        urlunsplit((urlsplit(u).scheme, urlsplit(u).netloc, urlsplit(u).path, "", ""))
        for u in seen_pages})
    target.param_endpoints = list(params)
    UI.ok(f"{result['pages']} pages | {len(params)} param-URLs | "
          f"{len(forms)} forms | {len(js)} js")
    for pe in params[:20]:
        UI.dim(f"      ? {pe['url']}  [{', '.join(pe['params'])}]")
    return result


def _r_crawl(d):
    lines = _sec("CRAWL / PARAMETERS")
    lines.append(f"  pages crawled: {d.get('pages', 0)}")
    params = d.get("params", [])
    if params:
        lines.append("  parameterized endpoints:")
        for pe in params:
            lines.append(f"    {pe['url']}  [{', '.join(pe['params'])}]")
    forms = d.get("forms", [])
    if forms:
        lines.append("  forms:")
        for fm in forms:
            lines.append(f"    {fm['method'].upper()} {fm['action']}  inputs: {', '.join(fm['inputs'])}")
    if d.get("js"):
        lines.append(f"  js files: {len(d['js'])}")
        for j in d["js"]:
            lines.append(f"    {j}")
    if not params and not forms:
        lines.append("  no parameters or forms found")
    return lines + [""]
