from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


_VCS_CHECKS = [
    ("/.git/HEAD",         re.compile(r"ref:\s*refs/"),                          "high",   ".git repository exposed"),
    ("/.git/config",       re.compile(r"\[core\]"),                              "high",   ".git config exposed"),
    ("/.env",              re.compile(r"(?m)^[A-Z0-9_]{2,}="),                   "high",   ".env file exposed"),
    ("/.svn/entries",      re.compile(r"(^\d+\s*$|dir|svn://)", re.I),           "medium", ".svn metadata exposed"),
    ("/.hg/requires",      re.compile(r"(revlog|store|dotencode)"),              "medium", "Mercurial repo exposed"),
    ("/config.php.bak",    re.compile(r"<\?php"),                                "high",   "PHP config backup exposed"),
    ("/config.php~",       re.compile(r"<\?php"),                                "high",   "PHP config backup exposed"),
    ("/wp-config.php.bak", re.compile(r"(<\?php|DB_PASSWORD)"),                  "high",   "wp-config backup exposed"),
    ("/.htaccess",         re.compile(r"(RewriteEngine|Order\s+allow|AuthType)", re.I), "medium", ".htaccess exposed"),
    ("/phpinfo.php",       re.compile(r"phpinfo\(\)|PHP Version"),               "high",   "phpinfo() exposed"),
    ("/server-status",     re.compile(r"Apache Server Status", re.I),            "medium", "Apache mod_status exposed"),
    ("/.aws/credentials",  re.compile(r"aws_access_key_id", re.I),               "high",   "AWS credentials exposed"),
    ("/id_rsa",            re.compile(r"PRIVATE KEY"),                           "high",   "SSH private key exposed"),
    ("/.DS_Store",         re.compile(r"Bud1"),                                  "low",    ".DS_Store exposed"),
]


_VCS_INFO = [
    ("/robots.txt",               re.compile(r"(?im)^\s*Disallow:")),
    ("/.well-known/security.txt", re.compile(r"(?i)contact:")),
    ("/sitemap.xml",              re.compile(r"<urlset|<sitemapindex")),
]


def phase_vcs(target, config, runner):
    result = {"findings": [], "info": [], "errors": []}
    target.ensure_web_services(config, runner)
    if not target.web_services:
        result["errors"].append("no web services")
        return result
    for svc in target.web_services:
        base = svc.url.rstrip("/")
        tag = svc.key().replace(":", "_")
        rnd = base + "/" + _rand(12) + ".zzq"
        cstat, chdr, cbody, _ = _curl_full(rnd, config, runner, f"vcs_catchall_{tag}")
        catchall = (cstat == "200" and bool(cbody))
        for path, sig, sev, desc in _VCS_CHECKS:
            url = base + path
            st, hd, body, _ = _curl_full(
                url, config, runner, "vcs_" + re.sub(r"\W+", "_", tag + path)[:40])
            if st != "200" or not body or not sig.search(body):
                continue
            if catchall and "html" in (hd.get("content-type", "").lower()):
                continue
            result["findings"].append({"url": url, "severity": sev, "desc": desc})
            UI.ok(f"EXPOSED [{sev}] {desc}  {url}")
        for path, sig in _VCS_INFO:
            url = base + path
            st, hd, body, _ = _curl_full(
                url, config, runner, "vcsinfo_" + re.sub(r"\W+", "_", tag + path)[:36])
            if st == "200" and body and sig.search(body):
                result["info"].append({"url": url})
                UI.dim(f"      info: {url}")
    if not result["findings"]:
        UI.dim("      no exposed sensitive files")
    return result


def _r_vcs(d):
    lines = _sec("SENSITIVE FILES / VCS EXPOSURE")
    fs = d.get("findings", [])
    if not fs and not d.get("info"):
        note = d.get("errors", [])
        return lines + ["  " + ("nothing exposed" if not note else note[0]), ""]
    for f in fs:
        lines.append(f"  [{f.get('severity','?')}] {f['desc']}  {f['url']}")
    for i in d.get("info", []):
        lines.append(f"  info: {i['url']}")
    return lines + [""]
