from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403

from huntnyx.discovery.ports import _r_ports, phase_ports
from huntnyx.discovery.fingerprint import _r_fingerprint, phase_fingerprint
from huntnyx.discovery.technologies import _r_technologies, phase_technologies
from huntnyx.enumeration.subdomains import _r_subdomains, phase_subdomains
from huntnyx.enumeration.vhost import _r_vhost, phase_vhost
from huntnyx.enumeration.crawl import _r_crawl, phase_crawl
from huntnyx.enumeration.jsanalysis import _r_jsanalysis, phase_jsanalysis
from huntnyx.enumeration.arjun import _r_arjun, phase_arjun
from huntnyx.enumeration.content import _r_content, phase_content
from huntnyx.enumeration.vcs import _r_vcs, phase_vcs
from huntnyx.testing.xss import _r_xss, phase_xss
from huntnyx.testing.xxe import _r_xxe, phase_xxe
from huntnyx.testing.cmdi import _r_cmdi, phase_cmdi
from huntnyx.testing.redirect import _r_redirect, phase_redirect
from huntnyx.testing.ssrf import _r_ssrf, phase_ssrf
from huntnyx.testing.traversal import _r_traversal, phase_traversal
from huntnyx.testing.ssti import _r_ssti, phase_ssti
from huntnyx.testing.sqlmap import _r_sqlmap, phase_sqlmap
from huntnyx.testing.secheaders import _r_secheaders, phase_secheaders
from huntnyx.testing.cors import _r_cors, phase_cors
from huntnyx.testing.bypass import _r_bypass, phase_bypass
from huntnyx.testing.nosqli import _r_nosqli, phase_nosqli
from huntnyx.testing.csrf import _r_csrf, phase_csrf
from huntnyx.testing.jwt import _r_jwt, phase_jwt


# ═══════════════════════════════════════════════════════════════════════
#  PHASE REGISTRY
# ═══════════════════════════════════════════════════════════════════════
PHASE_REGISTRY = [
    ("ports",        "Discovery",   "Ports",                 phase_ports,        _r_ports,        ["nmap"],                    False),
    ("fingerprint",  "Discovery",   "Fingerprint",           phase_fingerprint,  _r_fingerprint,  None,                        False),
    ("technologies", "Discovery",   "Technologies",          phase_technologies, _r_technologies, None,                        False),
    ("subdomains",   "Enumeration", "Subdomains",            phase_subdomains,   _r_subdomains,   ["subfinder"],               False),
    ("vhost",        "Enumeration", "VHosts / Subdomains",   phase_vhost,        _r_vhost,        ["ffuf"],                    False),
    ("crawl",        "Enumeration", "Crawl",                 phase_crawl,        _r_crawl,        None,                        False),
    ("jsanalysis",   "Enumeration", "JS Analysis",           phase_jsanalysis,   _r_jsanalysis,   None,                        False),
    ("arjun",        "Enumeration", "Arjun (hidden params)", phase_arjun,        _r_arjun,        ["arjun"],                   False),
    ("content",      "Enumeration", "Directories",           phase_content,      _r_content,      ["gobuster", "feroxbuster"], False),
    ("vcs",          "Enumeration", "Sensitive Files / VCS", phase_vcs,          _r_vcs,          None,                        False),
    ("xss",          "Testing",     "XSS",                   phase_xss,          _r_xss,          ["dalfox"],                  False),
    ("redirect",     "Testing",     "Open Redirect",         phase_redirect,     _r_redirect,     None,                        False),
    ("ssrf",         "Testing",     "SSRF",                  phase_ssrf,         _r_ssrf,         None,                        False),
    ("traversal",    "Testing",     "Path Traversal / LFI",  phase_traversal,    _r_traversal,    None,                        False),
    ("ssti",         "Testing",     "SSTI",                  phase_ssti,         _r_ssti,         None,                        False),
    ("cmdi",         "Testing",     "Command Injection",     phase_cmdi,         _r_cmdi,         None,                        False),
    ("xxe",          "Testing",     "XXE",                   phase_xxe,          _r_xxe,          None,                        False),
    ("secheaders",   "Testing",     "Security Headers",      phase_secheaders,   _r_secheaders,   None,                        False),
    ("cors",         "Testing",     "CORS Misconfiguration", phase_cors,         _r_cors,         None,                        False),
    ("csrf",         "Testing",     "CSRF",                  phase_csrf,         _r_csrf,         None,                        False),
    ("jwt",          "Testing",     "JWT Audit",             phase_jwt,          _r_jwt,          None,                        False),
    ("bypass",       "Testing",     "401/403 Bypass",        phase_bypass,       _r_bypass,       None,                        False),
    ("nosqli",       "Testing",     "NoSQL Injection",       phase_nosqli,       _r_nosqli,       None,                        False),
    ("sqlmap",       "Testing",     "SQLMap",                phase_sqlmap,       _r_sqlmap,       ["sqlmap"],                  True),
]

_K, _STAGE, _LABEL, _FN, _REND, _TOOLS, _OPTIN = range(7)
PHASE_ORDER = [r[_K] for r in PHASE_REGISTRY if not r[_OPTIN]]
STAGE_OF    = {r[_K]: r[_STAGE] for r in PHASE_REGISTRY}
PHASE_LABEL = {r[_K]: r[_LABEL] for r in PHASE_REGISTRY}
PHASES      = {r[_K]: r[_FN] for r in PHASE_REGISTRY}
RENDERERS   = {r[_K]: r[_REND] for r in PHASE_REGISTRY if r[_REND]}
PHASE_TOOL  = {r[_K]: r[_TOOLS] for r in PHASE_REGISTRY if r[_TOOLS]}
STAGES = []
for r in PHASE_REGISTRY:
    if r[_OPTIN]:
        continue
    if not STAGES or STAGES[-1][0] != r[_STAGE]:
        STAGES.append((r[_STAGE], []))
    STAGES[-1][1].append(r[_K])
ACTIVE_PHASES = next((phs for name, phs in STAGES if name == "Testing"), [])
SUMMARY_RENDER = {"endpoints": _r_endpoints, "parameters": _r_parameters}

_PHASE_EXTRA_TOOLS = {
    "fingerprint": ["curl"],
    "technologies": ["curl"],
}


def _stage_tools(stage):
    """Every tool / built-in test a stage can run, in registry order."""
    seen = []

    def push(x):
        if x and x not in seen:
            seen.append(x)

    for r in PHASE_REGISTRY:
        if r[_STAGE] != stage:
            continue
        key = r[_K]
        tools = PHASE_TOOL.get(key)
        if tools:
            for t in tools:
                push(t)
        for t in _PHASE_EXTRA_TOOLS.get(key, []):
            push(t)
        if not tools and key not in _PHASE_EXTRA_TOOLS:
            push(key)
    return ", ".join(seen)


STAGE_TOOLS = {name: _stage_tools(name) for name, _ in STAGES}
STAGE_TOOLS["Reporting"] = ""


def _stage_title(stage):
    tools = STAGE_TOOLS.get(stage, "")
    return f"{stage.upper()} ({tools})" if tools else stage.upper()

__all__ = [n for n in dir() if not n.startswith('__')]
