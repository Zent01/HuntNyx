from __future__ import annotations

import argparse
import copy
import datetime
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


# ════════════════════════════════════════════════════════════════════════
#  UI  ::  neon cyberpunk terminal styling
# ════════════════════════════════════════════════════════════════════════

class UI:
    PINK = (255, 0, 153)
    PURPLE = (157, 0, 255)
    CYAN = (0, 255, 255)
    GREEN = (57, 255, 20)
    YELLOW = (255, 210, 0)
    RED = (255, 45, 85)
    GREY = (120, 120, 140)
    WHITE = (235, 235, 245)

    enabled = True

    @classmethod
    def init(cls, force_no_color: bool) -> None:
        cls.enabled = (
            not force_no_color
            and sys.stdout.isatty()
            and os.environ.get("NO_COLOR") is None
            and os.environ.get("TERM") != "dumb"
        )

    @classmethod
    def c(cls, text: str, rgb, *, bold: bool = False) -> str:
        if not cls.enabled:
            return text
        r, g, b = rgb
        pre = ("\033[1m" if bold else "") + f"\033[38;2;{r};{g};{b}m"
        return f"{pre}{text}\033[0m"

    @classmethod
    def ok(cls, msg): print(f"  {cls.c('[+]', cls.GREEN, bold=True)} {msg}")

    @classmethod
    def info(cls, msg): print(f"  {cls.c('[*]', cls.CYAN, bold=True)} {msg}")

    @classmethod
    def warn(cls, msg): print(f"  {cls.c('[!]', cls.YELLOW, bold=True)} {msg}")

    @classmethod
    def err(cls, msg): print(f"  {cls.c('[-]', cls.RED, bold=True)} {msg}")

    @classmethod
    def dim(cls, msg): print(cls.c(msg, cls.GREY))

    @classmethod
    def phase(cls, name):
        bar = cls.c("▓▓", cls.PINK, bold=True)
        title = cls.c(f" {name.upper()} ", cls.CYAN, bold=True)
        line = cls.c("─" * max(4, 46 - len(name)), cls.PURPLE)
        print(f"\n{bar}{title}{line}")

    @classmethod
    def kv(cls, key, val):
        print(f"  {cls.c(key + ':', cls.PURPLE, bold=True)} {cls.c(val, cls.WHITE)}")

    _GLYPHS = {
        "W": ["██╗    ██╗", "██║    ██║", "██║ █╗ ██║", "██║███╗██║", "╚███╔███╔╝", " ╚══╝╚══╝ "],
        "E": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
        "B": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██████╔╝", "╚═════╝ "],
        "N": ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
        "U": ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
        "M": ["███╗   ███╗", "████╗ ████║", "██╔████╔██║", "██║╚██╔╝██║", "██║ ╚═╝ ██║", "╚═╝     ╚═╝"],
        "Y": ["██╗   ██╗", "╚██╗ ██╔╝", " ╚████╔╝ ", "  ╚██╔╝  ", "   ██║   ", "   ╚═╝   "],
        "X": ["██╗  ██╗", "╚██╗██╔╝", " ╚███╔╝ ", " ██╔██╗ ", "██╔╝ ██╗", "╚═╝  ╚═╝"],
        "H": ["██╗  ██╗", "██║  ██║", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
        "T": ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
    }

    @classmethod
    def _word(cls, letters, gap="  "):
        rows = ["".join(cls._GLYPHS[ch][r] + gap for ch in letters) for r in range(6)]
        return rows

    @staticmethod
    def _grad(n):
        stops = [UI.PINK, UI.PURPLE, UI.CYAN]
        out = []
        for i in range(n):
            t = (i / max(1, n - 1)) * (len(stops) - 1)
            lo = int(t)
            hi = min(lo + 1, len(stops) - 1)
            f = t - lo
            a, b = stops[lo], stops[hi]
            out.append(tuple(int(a[j] + (b[j] - a[j]) * f) for j in range(3)))
        return out

    @classmethod
    def banner(cls):
        # Συνδυάζουμε HUNT και NYX σε μία γραμμή, με έναν δαίμονα ανάμεσα
        sep = ["  ╲   ╱     ", "  ╲╲ ╱╱     ", "  ▟▔▔▔▙     ",
               "  ▜◣ ◢▛     ", "   ╲▽╱      ", "    ╹       "]
        art = [h + s + n for h, s, n in zip(cls._word("HUNT"), sep, cls._word("NYX"))]
        grad = cls._grad(len(art))
        print()
        for line, col in zip(art, grad):
            print("  " + cls.c(line, col, bold=True))
        print()

    @classmethod
    def clear(cls):
        if not sys.stdout.isatty():
            return
        # Flush first: any prompt output still buffered must be emitted BEFORE
        # the clear, otherwise it prints on top of the freshly-cleared screen
        # (looks like the screen "didn't get cleared in time").
        sys.stdout.flush()
        if os.name == "nt":
            # Windows cmd/PowerShell don't honor ANSI clears reliably
            os.system("cls")
        else:
            # hard clear via terminfo, then drop scrollback (3J) + home cursor
            os.system("clear")
            sys.stdout.write("\033[3J\033[H")
            sys.stdout.flush()

    @classmethod
    def ask(cls, prompt, default=None, *, color=None):
        color = color or cls.CYAN
        arrow = cls.c("▶", cls.PINK, bold=True)
        m = re.search(r"\s*\(([^)]*)\)\s*$", prompt)
        if m:
            q = cls.c(prompt[:m.start()].strip(), color) + cls.c(f"  ({m.group(1)})", cls.GREY)
        else:
            q = cls.c(prompt, color)
        d = cls.c(f" [{default}]", cls.PURPLE) if default else ""
        try:
            val = input(f"{arrow} {q}{d} ").strip()
        except EOFError:
            val = ""
        return val or (default or "")

    @classmethod
    def ask_yes_no(cls, prompt, default=True, *, color=None):
        val = cls.ask(f"{prompt} ({'Y/n' if default else 'y/N'})", color=color).lower()
        return default if not val else val in ("y", "yes")

    @classmethod
    def _input(cls, rendered):
        try:
            return input(rendered).strip()
        except EOFError:
            return ""

    @classmethod
    def ask_warn(cls, prompt, hint=""):
        """A warning-style prompt: yellow [!] marker + yellow question."""
        mark = cls.c("[!]", cls.YELLOW, bold=True)
        q = cls.c(prompt, cls.YELLOW)
        h = cls.c(f"  ({hint})", cls.GREY) if hint else ""
        return cls._input(f"  {mark} {q}{h} ")


# ════════════════════════════════════════════════════════════════════════
#  CONFIG
# ════════════════════════════════════════════════════════════════════════

DEFAULTS: dict = {
    "threads": 40,
    "default_web_ports": [80, 443, 8080, 8000, 8443],
    "https_ports": [443, 8443, 4443],
    "wordlists": {
        "content": "",
        "vhost": "",
    },
    "extensions": ["php", "html", "txt"],
    "timeouts": {"nmap": 1800, "gobuster": 600, "ffuf": 900, "feroxbuster": 900,
                 "curl": 15, "tls": 15, "subfinder": 600,
                 "arjun": 900, "sqlmap": 1800, "dalfox": 600, "default": 300},
    "nmap": {"top_ports": 1000, "full_scan": True, "scripts": True, "extra_args": []},
    "content": {"status_codes": "", "req_timeout": "10s"},
    "vhost": {"filter_codes": "", "filter_size": "", "extra_args": []},
    "crawl": {"max_pages": 40, "max_depth": 2, "timeout": 10},
    "arjun": {"max_urls": 25, "stable": True, "req_timeout": 10, "wordlist": "",
              "extra_args": []},
    "sqlmap": {"level": 2, "risk": 2, "max_targets": 15, "extra_args": []},
    "dalfox": {"extra_args": []},
    "subfinder": {"max_add": 25, "extra_args": []},
    "active": {"timeout": 10, "delay": 0, "max_endpoints": 60},
    "sqli": {"time_based": True, "sleep": 5},
    "redirect": {"canary": "https://www.youtube.com"},
    "ssrf": {"metadata": True, "file_scheme": True, "collaborator": ""},
    "jsanalysis": {"max_files": 40, "max_endpoints_fed": 80},
    "csrf": {"max_forms": 60},
    "jwt": {"wordlist": "", "crack": True},
    # Per-vulnerability-class severity. Users can override any entry in their
    # config.json; a "review"/tentative finding is auto-downgraded one step.
    "severity": {
        "ssti": "critical", "cmdi": "critical", "sqli": "critical", "sqlmap": "critical",
        "xxe": "high", "traversal": "high", "nosqli": "high", "xss": "high",
        "ssrf": "high", "bypass": "high", "cors": "high", "jwt": "high", "vcs": "high",
        "redirect": "medium", "csrf": "medium", "jsanalysis": "medium",
        "secheaders": "low",
    },
}


def _deep_merge(base, override):
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        out[k] = _deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


class Config:
    def __init__(self, data): self._data = data

    @classmethod
    def load(cls, path):
        data = copy.deepcopy(DEFAULTS)
        if path and os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    data = _deep_merge(data, json.load(fh) or {})
            except Exception as exc:
                UI.warn(f"could not parse {path} ({exc}) — using defaults")
        return cls(data)

    def get(self, dotted, default=None):
        node = self._data
        for part in dotted.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node

    def set(self, dotted, value):
        parts = dotted.split(".")
        node = self._data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value

    def apply_overrides(self, threads=None):
        if threads is not None:
            self._data["threads"] = threads


# ════════════════════════════════════════════════════════════════════════
#  DEPENDENCIES
# ════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Tool:
    name: str
    phases: tuple
    required: bool = True
    note: str = ""


BASE_TOOLS = (
    Tool("nmap", ("ports",), True, "core port/service discovery"),
    Tool("curl", ("fingerprint",), True, "HTTP headers / TLS probing"),
)
ENGINE_TOOLS = ("gobuster", "feroxbuster", "ffuf", "arjun", "sqlmap", "dalfox", "subfinder", "cewl")


@dataclass
class DepReport:
    found: dict = field(default_factory=dict)
    missing: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    @property
    def ok(self):
        return not any(t.required for t in self.missing)


def dep_check(required_phases=None):
    rep = DepReport()
    for tool in BASE_TOOLS:
        path = shutil.which(tool.name)
        if path:
            rep.found[tool.name] = path
            continue
        relevant = required_phases is None or bool(set(tool.phases) & required_phases)
        if not relevant:
            continue
        (rep.missing if tool.required else rep.warnings).append(
            tool if tool.required else f"optional '{tool.name}' not found — {tool.note}")

    for eng in ENGINE_TOOLS:
        p = shutil.which(eng)
        if p:
            rep.found[eng] = p

    scope = required_phases
    if (scope is None or "content" in scope) and not (
            "gobuster" in rep.found or "feroxbuster" in rep.found):
        rep.missing.append(Tool("gobuster|feroxbuster", ("content",), True,
                                "content discovery engine"))
    if (scope is None or "vhost" in scope) and "ffuf" not in rep.found:
        rep.missing.append(Tool("ffuf", ("vhost",), True, "vhost fuzzing engine"))
    if "arjun" not in rep.found:
        rep.warnings.append("optional 'arjun' not found — arjun phase will be skipped")
    if "sqlmap" not in rep.found:
        rep.warnings.append("optional 'sqlmap' not found — --sqlmap will be skipped")
    if "dalfox" not in rep.found:
        rep.warnings.append("optional 'dalfox' not found — XSS phase will be skipped")
    if "subfinder" not in rep.found:
        rep.warnings.append("optional 'subfinder' not found — subdomains phase will be skipped")
    if "cewl" not in rep.found:
        rep.warnings.append("optional 'cewl' not found — custom wordlist building will be skipped")
    return rep


def print_dep_report(rep):
    UI.phase("dependency check")
    for name, path in sorted(rep.found.items()):
        UI.ok(f"{name:<12} {UI.c(path, UI.GREY)}")
    for w in rep.warnings:
        UI.warn(w)
    for t in rep.missing:
        UI.err(f"{t.name:<20} {t.note}")
    if rep.missing:
        UI.dim("      install: sudo apt install -y nmap gobuster ffuf seclists")
        UI.dim("               arjun: pipx install arjun ; dalfox: go install github.com/hahwul/dalfox/v2@latest")
    status = UI.c("READY", UI.GREEN, bold=True) if rep.ok else UI.c("BLOCKED", UI.RED, bold=True)
    print(f"  status: {status}")


def _show_file(label, path):
    """Print a file the tool will use, with an exists/missing marker."""
    if not path:
        print(f"  {UI.c(label + ':', UI.PURPLE, bold=True)} {UI.c('not set', UI.RED)}")
        return
    ok = os.path.isfile(path)
    mark = UI.c("ok", UI.GREEN, bold=True) if ok else UI.c("missing", UI.RED, bold=True)
    print(f"  {UI.c(label + ':', UI.PURPLE, bold=True)} {UI.c(path, UI.WHITE)}  [{mark}]")


# ════════════════════════════════════════════════════════════════════════
#  RUNNER
# ════════════════════════════════════════════════════════════════════════

@dataclass
class RunResult:
    cmd: list
    returncode: int | None
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
    log_path: str | None = None
    error: str | None = None

    @property
    def cmdline(self):
        return " ".join(shlex.quote(c) for c in self.cmd)


# Flags whose following argv value is always a secret (cookies, request bodies,
# credentials) and must never be written to logs or echoed in verbose output.
_REDACT_FULL_FLAGS = {"-b", "--cookie", "-c", "--data", "--data-binary",
                      "--data-raw", "--data-ascii", "--login-data", "--headers"}
_HEADER_FLAGS = {"-H", "--header"}
_SENSITIVE_HDR_RE = re.compile(
    r"^\s*(authorization|cookie|proxy-authorization|[\w-]*token[\w-]*|"
    r"[\w-]*csrf[\w-]*|[\w-]*api[_-]?key[\w-]*|[\w-]*secret[\w-]*)\s*:", re.I)


def _redact_cmdline(cmd):
    """Quote a command for display/logging, masking secret values. Cookie /
    body / credential flag values are fully masked; header values are masked
    only when the header name looks sensitive (Authorization, tokens, etc.),
    so benign headers (User-Agent, Host: FUZZ.x) stay debuggable."""
    out, redact_next, hdr_next = [], False, False
    for tok in cmd:
        if redact_next:
            out.append("<redacted>")
            redact_next = False
            continue
        if hdr_next:
            hdr_next = False
            if _SENSITIVE_HDR_RE.match(tok):
                name = tok.split(":", 1)[0].strip()
                out.append(shlex.quote(f"{name}: <redacted>"))
                continue
            out.append(shlex.quote(tok))
            continue
        out.append(shlex.quote(tok))
        if tok in _REDACT_FULL_FLAGS:
            redact_next = True
        elif tok in _HEADER_FLAGS:
            hdr_next = True
    return " ".join(out)


@dataclass
class Runner:
    log_dir: Path
    verbose: bool = False
    quiet: bool = False
    default_timeout: int = 300

    def vlog(self, msg):
        if self.verbose and not self.quiet:
            UI.dim(f"    $ {msg}")

    def _heartbeat(self, log_name, stop):
        n = 0
        while not stop.wait(15):
            n += 15
            if self.quiet:
                continue
            if sys.stdout.isatty():
                sys.stdout.write(UI.c(f"\r      … {log_name} running {n}s ", UI.GREY))
                sys.stdout.flush()
            else:
                print(f"      … {log_name} running {n}s")

    def run(self, cmd, *, log_name, timeout=None, cwd=None, heartbeat=False):
        timeout = timeout or self.default_timeout
        log_file = self.log_dir / f"{log_name}.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        self.vlog(_redact_cmdline(cmd))
        start = time.time()
        stop = threading.Event()
        beat = None
        if heartbeat and not self.quiet:
            beat = threading.Thread(target=self._heartbeat, args=(log_name, stop), daemon=True)
            beat.start()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                  cwd=cwd, stdin=subprocess.DEVNULL)
            res = RunResult(cmd, proc.returncode, proc.stdout or "", proc.stderr or "",
                            time.time() - start, log_path=str(log_file))
        except subprocess.TimeoutExpired as exc:
            so, se = exc.stdout or "", exc.stderr or ""
            res = RunResult(cmd, None,
                            so.decode(errors="replace") if isinstance(so, bytes) else so,
                            se.decode(errors="replace") if isinstance(se, bytes) else se,
                            time.time() - start, timed_out=True, log_path=str(log_file))
            if not self.quiet:
                UI.warn(f"timed out after {timeout}s: {log_name} (using partial results)")
        except FileNotFoundError:
            res = RunResult(cmd, None, "", "", time.time() - start,
                            error=f"binary not found: {cmd[0]}", log_path=str(log_file))
            if not self.quiet:
                UI.err(f"not found: {cmd[0]}")
        except Exception as exc:
            res = RunResult(cmd, None, "", "", time.time() - start,
                            error=str(exc), log_path=str(log_file))
        finally:
            stop.set()
            if beat:
                beat.join(timeout=1)
                if sys.stdout.isatty() and not self.quiet:
                    sys.stdout.write("\r" + " " * 50 + "\r")
                    sys.stdout.flush()
        self._write_log(log_file, res)
        return res

    @staticmethod
    def _write_log(log_file, res):
        with open(log_file, "w", encoding="utf-8") as fh:
            fh.write(f"# cmd: {_redact_cmdline(res.cmd)}\n")
            fh.write(f"# rc: {res.returncode}  timed_out: {res.timed_out}  {res.duration:.1f}s\n")
            if res.error:
                fh.write(f"# error: {res.error}\n")
            fh.write("# --- stdout ---\n" + res.stdout)
            if res.stderr.strip():
                fh.write("\n# --- stderr ---\n" + res.stderr)


# ════════════════════════════════════════════════════════════════════════
#  TARGET
# ════════════════════════════════════════════════════════════════════════

@dataclass
class WebService:
    host: str
    port: int
    scheme: str

    @property
    def url(self):
        default = (self.scheme == "http" and self.port == 80) or \
                  (self.scheme == "https" and self.port == 443)
        return f"{self.scheme}://{self.host}" if default else f"{self.scheme}://{self.host}:{self.port}"

    def key(self):
        return f"{self.host}:{self.port}:{self.scheme}"


class Target:
    def __init__(self, raw, workdir):
        self.raw = raw
        raw = (raw or "").strip()
        m = re.match(r"^(?P<scheme>[a-zA-Z][\w+.\-]*)://", raw)
        scheme = m.group("scheme").lower() if m else None
        rest = raw[m.end():] if m else raw
        slash = rest.find("/")
        netloc = rest[:slash] if slash != -1 else rest
        path = rest[slash:] if slash != -1 else ""
        if ":" in netloc and not netloc.endswith(":"):
            host, _, port_s = netloc.rpartition(":")
            port = int(port_s) if port_s.isdigit() else None
        else:
            host, port = netloc, None

        self.name = host or netloc or raw
        self.base = Path(workdir)
        self.raw_dir = self.base / "raw"
        self.artifacts_dir = self.base / "artifacts"
        self.web_services: list[WebService] = []
        self.param_endpoints: list = []
        self.seed_urls: list = []
        self.extra_forms: list = []
        self.results: dict = {}

        if scheme in ("http", "https") or port is not None:
            sch = scheme if scheme in ("http", "https") else \
                ("https" if port in (443, 8443, 4443) else "http")
            prt = port if port is not None else (443 if sch == "https" else 80)
            self.add_web_service(prt, sch)
            if path and path not in ("", "/"):
                self.seed_urls.append(self.web_services[-1].url.rstrip("/") + path)

    def prepare(self):
        for d in (self.raw_dir, self.artifacts_dir):
            d.mkdir(parents=True, exist_ok=True)

    def add_web_service(self, port, scheme, host=None):
        svc = WebService(host or self.name, int(port), scheme)
        if svc.key() not in {s.key() for s in self.web_services}:
            self.web_services.append(svc)

    def seed_from_ports_list(self, ports_csv, https_ports):
        for tok in ports_csv.split(","):
            tok = tok.strip()
            if tok.isdigit():
                port = int(tok)
                self.add_web_service(port, "https" if port in set(https_ports) else "http")

    def ensure_web_services(self, config, runner):
        if self.web_services:
            return
        UI.info("no web services known — probing default ports")
        https_ports = set(config.get("https_ports", []))
        timeout = config.get("timeouts.curl", 15)
        for port in config.get("default_web_ports", []):
            scheme = "https" if port in https_ports else "http"
            url = WebService(self.name, port, scheme).url
            res = runner.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                              "--max-time", str(timeout), "-k", *auth_curl(config), url],
                             log_name=f"probe_{scheme}_{port}", timeout=timeout + 5)
            code = (res.stdout or "").strip()
            if code and code != "000":
                self.add_web_service(port, scheme)
                UI.ok(f"{url} -> HTTP {code}")


# ════════════════════════════════════════════════════════════════════════
#  AUTH
# ════════════════════════════════════════════════════════════════════════

def auth_curl(config):
    args = []
    if config.get("_cookie"):
        args += ["-b", config.get("_cookie")]
    for h in config.get("_headers", []) or []:
        args += ["-H", h]
    return args


def auth_header_pairs(config):
    pairs = list(config.get("_headers", []) or [])
    if config.get("_cookie"):
        pairs.append("Cookie: " + config.get("_cookie"))
    return pairs



import html.parser as _htmlparser
import ssl as _ssl
from urllib.parse import urljoin, urlparse, urlsplit, parse_qs
from urllib.request import Request, build_opener, HTTPSHandler


class _LinkParser(_htmlparser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.forms, self.assets, self._cur = [], [], [], None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a" and d.get("href"):
            self.links.append(d["href"])
        elif tag == "script" and d.get("src"):
            self.links.append(d["src"])
        elif tag in ("img", "iframe", "source", "embed", "video", "audio") \
                and (d.get("src") or d.get("href")):
            self.assets.append(d.get("src") or d.get("href"))
        elif tag == "link" and d.get("href"):
            self.assets.append(d["href"])
        elif tag == "form":
            self._cur = {"action": d.get("action", ""),
                         "method": (d.get("method") or "get").lower(), "inputs": []}
            self.forms.append(self._cur)
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            if d.get("name"):
                self._cur["inputs"].append(d["name"])

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def _crawl_headers(config):
    h = {"User-Agent": "HuntNyx/1.0"}
    for pair in config.get("_headers", []) or []:
        if ":" in pair:
            k, _, v = pair.partition(":")
            h[k.strip()] = v.strip()
    if config.get("_cookie"):
        h["Cookie"] = config.get("_cookie")
    return h






# --- arjun (hidden GET-parameter discovery) --------------------------------





# ════════════════════════════════════════════════════════════════════════
#  ACTIVE CHECKS
# ════════════════════════════════════════════════════════════════════════

from urllib.parse import urlencode, urlunsplit, quote


def _active_targets(target):
    out, seen = [], set()

    def add(url, params):
        params = [p for p in (params or []) if p]
        if not url or not params:
            return
        sp = urlsplit(url)
        clean = f"{sp.scheme}://{sp.netloc}{sp.path}"
        sig = (sp.path, tuple(sorted(params)))
        if sig in seen:
            return
        seen.add(sig)
        out.append({"url": clean, "params": list(params)})

    for pe in getattr(target, "param_endpoints", []):
        add(pe.get("url"), pe.get("params", []))
    for su in getattr(target, "seed_urls", []):
        sp = urlsplit(su)
        if sp.query:
            add(su, list(parse_qs(sp.query, keep_blank_values=True).keys()))
    return out


def _get(url, params, config, timeout):
    headers = _crawl_headers(config)
    sp = urlsplit(url)
    qs = urlencode(params, doseq=True)
    full = urlunsplit((sp.scheme, sp.netloc, sp.path, qs, ""))
    ctx = _ssl._create_unverified_context()
    opener = build_opener(HTTPSHandler(context=ctx))
    start = time.time()
    try:
        with opener.open(Request(full, headers=headers), timeout=timeout) as r:
            body = r.read(300_000).decode("utf-8", "replace")
            return r.status if hasattr(r, "status") else r.getcode(), body, time.time() - start
    except Exception as exc:
        body = getattr(exc, "read", lambda: b"")()
        try:
            body = body.decode("utf-8", "replace")
        except Exception:
            body = ""
        code = getattr(exc, "code", None)
        return code, body, time.time() - start


def _post(url, data, config, timeout):
    headers = _crawl_headers(config)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    body_bytes = urlencode(data, doseq=True).encode()
    ctx = _ssl._create_unverified_context()
    opener = build_opener(HTTPSHandler(context=ctx))
    start = time.time()
    try:
        with opener.open(Request(url, data=body_bytes, headers=headers, method="POST"),
                         timeout=timeout) as r:
            body = r.read(300_000).decode("utf-8", "replace")
            return r.status if hasattr(r, "status") else r.getcode(), body, time.time() - start
    except Exception as exc:
        body = getattr(exc, "read", lambda: b"")()
        try:
            body = body.decode("utf-8", "replace")
        except Exception:
            body = ""
        return getattr(exc, "code", None), body, time.time() - start


def _post_forms(target):
    crawl = target.results.get("crawl") or {}
    forms = [f for f in crawl.get("forms", [])
             if f.get("method") == "post" and f.get("inputs")]
    forms += [f for f in getattr(target, "extra_forms", [])
              if f.get("method") == "post" and f.get("inputs")]
    return forms


# ════════════════════════════════════════════════════════════════════════
#  CHECKPOINT / RESUME
# ════════════════════════════════════════════════════════════════════════
_STATE_VERSION = 1


def _state_slug(target):
    s = re.sub(r"^\w+://", "", (target or "").strip()).strip("/")
    s = re.sub(r"[^A-Za-z0-9._-]", "_", s)
    return re.sub(r"_+", "_", s).strip("_") or "target"


def state_path_for(target_name, explicit=None):
    """Where a run's checkpoint lives. Unlike the scan temp dir, this file
    persists between runs so `--resume` can pick up where a run left off."""
    return explicit or os.path.abspath(f"{_state_slug(target_name)}_state.json")


def save_state(path, target, phases, completed):
    """Atomically write a checkpoint of completed phases + the reconstructable
    parts of the target. Called after each phase so a crash/Ctrl-C still leaves
    a resumable checkpoint. Best-effort: never raises."""
    data = {
        "version": _STATE_VERSION,
        "saved": datetime.datetime.now().isoformat(timespec="seconds"),
        "target": target.raw,
        "name": target.name,
        "phases": list(phases),
        "completed": list(completed),
        "web_services": [{"host": s.host, "port": s.port, "scheme": s.scheme}
                         for s in target.web_services],
        "seed_urls": list(getattr(target, "seed_urls", [])),
        "param_endpoints": list(getattr(target, "param_endpoints", [])),
        "extra_forms": list(getattr(target, "extra_forms", [])),
        "results": {k: target.results.get(k) for k in completed
                    if target.results.get(k) is not None},
    }
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, default=str)
        os.replace(tmp, path)
        return True
    except Exception as exc:
        UI.warn(f"could not write checkpoint {path}: {exc}")
        return False


def load_state(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        UI.warn(f"could not read checkpoint {path}: {exc}")
        return None
    if data.get("version") != _STATE_VERSION:
        UI.warn(f"checkpoint version mismatch in {path} — ignoring it")
        return None
    return data


def apply_state(target, state):
    """Restore completed-phase results and the reconstructable target fields so
    later phases (and the report) see the earlier findings. Returns the set of
    already-completed phase keys."""
    for ws in state.get("web_services", []):
        try:
            target.add_web_service(ws["port"], ws["scheme"], host=ws.get("host"))
        except Exception:
            pass
    for u in state.get("seed_urls", []):
        if u not in target.seed_urls:
            target.seed_urls.append(u)
    for pe in state.get("param_endpoints", []):
        if pe not in target.param_endpoints:
            target.param_endpoints.append(pe)
    for fm in state.get("extra_forms", []):
        if fm not in target.extra_forms:
            target.extra_forms.append(fm)
    for key, val in (state.get("results") or {}).items():
        if val is not None:
            target.results[key] = val
    return set(state.get("completed", []))


# ════════════════════════════════════════════════════════════════════════
#  SEVERITY SCORING
# ════════════════════════════════════════════════════════════════════════
_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _sev_rank(sev):
    try:
        return _SEV_ORDER.index(sev)
    except ValueError:
        return 0


def _downgrade_sev(sev):
    """Lower a severity by one step (used for tentative/review findings)."""
    return _SEV_ORDER[max(0, _sev_rank(sev) - 1)]


def severity_for(vuln, config, review=False):
    """Hybrid severity: per-class default (config-overridable), auto-downgraded
    one step for tentative/review findings."""
    base = (config.get("severity") or {}).get(vuln, "info")
    return _downgrade_sev(base) if review else base


def _finding_label(phase, f):
    """One-line human label for a finding, tolerant of every phase shape."""
    if not isinstance(f, dict):
        return str(f)[:100]
    if f.get("desc") and f.get("url"):                       # vcs
        return f"{f['desc']}  {f['url']}"
    if f.get("class") and f.get("url"):                      # cors
        cred = " +creds" if f.get("acac") else ""
        return f"{f['class']}{cred}  {f['url']}"
    if f.get("msg"):                                          # header-style
        return f["msg"]
    url = f.get("url") or f.get("action") or ""
    param = f.get("param")
    method = f.get("method", "")
    tail = f"  [{param}]" if param else ""
    extra = f"  ({f['probe']})" if f.get("probe") else ""
    return f"{method} {url}{tail}{extra}".strip()


def _iter_findings(target, config):
    """Normalize findings across every phase shape into
    (severity, phase, label, review) tuples for the executive summary."""
    out = []
    for phase, data in (target.results or {}).items():
        if not isinstance(data, dict):
            continue
        base = severity_for(phase, config)

        # injection-framework shape: {confirmed:[], review:[]}
        if "confirmed" in data or ("review" in data and "findings" not in data):
            for f in data.get("confirmed", []):
                out.append((base, phase, _finding_label(phase, f), False))
            for f in data.get("review", []):
                out.append((_downgrade_sev(base), phase, _finding_label(phase, f) + " (review)", True))
            continue

        # secheaders shape: {services:[{findings:[{sev,msg}]}]}
        if phase == "secheaders" and "services" in data:
            for s in data.get("services", []):
                for hf in s.get("findings", []):
                    sev = hf.get("sev", "info")
                    if _sev_rank(sev) >= _sev_rank("low"):
                        out.append((sev, phase, f"{hf.get('msg','')}  @ {s.get('url','')}", False))
            continue

        # sqlmap shape
        if phase == "sqlmap" and "injectable" in data:
            for inj in data.get("injectable", []):
                out.append((base, phase, _finding_label(phase, inj), False))
            continue

        # generic {findings:[...]} shape (ssrf, redirect, xss, cors, bypass,
        # vcs, csrf, jwt, jsanalysis, ...)
        for f in data.get("findings", []):
            review = bool(isinstance(f, dict) and f.get("review"))
            sev = (f.get("severity") if isinstance(f, dict) else None) \
                or severity_for(phase, config, review)
            out.append((sev, phase, _finding_label(phase, f), review))
    return out


def _findings_overview(target, config, limit=50):
    """Executive summary section: counts by severity + a severity-ranked list.
    The '[sev]' tags are picked up by the report colorizer."""
    items = _iter_findings(target, config)
    lines = _sec("FINDINGS SUMMARY (by severity)")
    if not items:
        return lines + ["  no findings recorded", ""]
    counts = {s: 0 for s in _SEV_ORDER}
    for sev, _p, _l, _r in items:
        counts[sev] = counts.get(sev, 0) + 1
    tally = "   ".join(f"{s}: {counts[s]}" for s in reversed(_SEV_ORDER) if counts.get(s))
    lines.append("  " + tally)
    lines.append("")
    ranked = sorted(items, key=lambda t: (-_sev_rank(t[0]), t[1]))
    for sev, phase, label, _r in ranked[:limit]:
        lines.append(f"  [{sev}] {phase}: {label}")
    if len(ranked) > limit:
        lines.append(f"  … +{len(ranked) - limit} more")
    return lines + [""]


# --- XSS via dalfox --------------------------------------------------------







# --- sqlmap auto hand-off --------------------------------------------------





# ════════════════════════════════════════════════════════════════════════
#  MODULES  ::  discovery/enumeration summaries + testing checks
# ════════════════════════════════════════════════════════════════════════

def _curl_full(url, config, runner, tag, extra=None):
    """GET with -i; return (status, headers_dict, body, RunResult). Auth-aware.
    ΠΡΟΣΟΧΗ: ΔΕΝ ακολουθεί redirects (--max-redirs 0)."""
    timeout = config.get("timeouts.curl", 15)
    cmd = ["curl", "-s", "-i", "-k",
           "--max-time", str(timeout),
           "--max-redirs", "0",
           *auth_curl(config)]
    if extra:
        cmd += extra
    cmd += [url]
    res = runner.run(cmd, log_name=tag, timeout=timeout + 5)
    raw = res.stdout or ""
    sep = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
    head, _, body = raw.partition(sep)
    headers, status = {}, ""
    for line in head.splitlines():
        if line.startswith("HTTP/"):
            m = re.search(r"\s(\d{3})\b", line)
            if m:
                status = m.group(1)
            continue
        if ":" in line:
            k, _, v = line.partition(":")
            key = k.strip().lower()
            headers[key] = (headers[key] + "; " + v.strip()) if key in headers else v.strip()
    return status, headers, body, res


def _build_url(url, params):
    sp = urlsplit(url)
    return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(params, doseq=True), ""))


# --- Discovery: technologies -----------------------------------------------





# --- Enumeration summaries: endpoints, parameters --------------------------

def _summarize_endpoints(target):
    result = {"endpoints": [], "errors": []}
    urls = set()
    crawl = target.results.get("crawl") or {}
    for pe in crawl.get("params", []):
        urls.add(pe.get("url"))
    for fm in crawl.get("forms", []):
        urls.add(fm.get("action"))
    for j in crawl.get("js", []):
        urls.add(j)
    content = target.results.get("content") or {}
    for e in content.get("services", []):
        for f in e.get("found", []):
            urls.add(e.get("url", "").rstrip("/") + "/" + (f.get("path") or "").lstrip("/"))
    for su in getattr(target, "seed_urls", []):
        urls.add(su)
    for s in target.web_services:
        urls.add(s.url)
    result["endpoints"] = sorted(u for u in urls if u)
    return result


def _summarize_parameters(target):
    result = {"params": [], "errors": []}
    seen = set()
    out = []
    for pe in getattr(target, "param_endpoints", []):
        key = (pe.get("url"), tuple(pe.get("params", [])))
        if key not in seen:
            seen.add(key)
            out.append({"url": pe.get("url"), "params": pe.get("params", []), "where": "GET"})
    crawl = target.results.get("crawl") or {}
    for fm in crawl.get("forms", []):
        key = (fm.get("action"), tuple(fm.get("inputs", [])))
        if key not in seen:
            seen.add(key)
            out.append({"url": fm.get("action"), "params": fm.get("inputs", []),
                        "where": fm.get("method", "get").upper() + " form"})
    result["params"] = out
    return result


# --- Testing: security headers ---------------------------------------------





# --- Testing: open redirect (enhanced) -------------------------------------



















def _read_cookie_jar(path):
    """Parse a curl Netscape cookie jar -> {name: value} (handles #HttpOnly_)."""
    cookies = {}
    try:
        for line in open(path, encoding="utf-8", errors="ignore"):
            line = line.rstrip("\n")
            if line.startswith("#HttpOnly_"):
                line = line[len("#HttpOnly_"):]
            elif not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 7 and parts[6]:
                cookies[parts[5]] = parts[6]
    except Exception:
        pass
    return cookies


def _find_login_form(target, config, runner):
    """Fetch likely login pages and return (action_url, [field_names]) for the
    first POST form with a password field. Honors config _login_url."""
    candidates = []
    if config.get("_login_url"):
        candidates.append(config.get("_login_url"))
    for svc in target.web_services:
        base = svc.url.rstrip("/")
        for p in ("/login", "/signin", "/sign-in", "/account/login", "/user/login",
                  "/auth/login", "/users/sign_in", "/accounts/login"):
            candidates.append(base + p)
    candidates += list(getattr(target, "seed_urls", []))
    seen = set()
    for url in candidates:
        if not url or url in seen:
            continue
        seen.add(url)
        _s, _h, body, _r = _curl_full(url, config, runner, "login_probe")
        if not body:
            continue
        p = _LinkParser()
        try:
            p.feed(body)
        except Exception:
            continue
        for f in p.forms:
            names = [str(i).lower() for i in f["inputs"]]
            if f["method"] == "post" and any("pass" in n for n in names):
                return urljoin(url, f["action"] or ""), f["inputs"]
    return None, None


def _auto_login(target, config, runner):
    """Log in with provided creds, capture the session cookie, and set it as the
    scan identity so crawl + all modules test POST-LOGIN pages. Needs valid
    credentials in --login-data (dummy creds won't unlock authenticated pages)."""
    creds = config.get("_login_data")
    if not creds:
        return False
    target.ensure_web_services(config, runner)
    action, fields = _find_login_form(target, config, runner)
    if not action:
        UI.warn("auto-login: no login form found (try --login-url)")
        return False
    timeout = config.get("timeouts.curl", 15)
    jar = str(target.artifacts_dir / "login_cookies.txt")
    UI.info(f"auto-login -> {UI.c(action, UI.WHITE)}")
    runner.run(["curl", "-s", "-i", "-k", "--max-time", str(timeout), "-c", jar,
                *auth_curl(config), "--data", creds, action],
               log_name="auto_login", timeout=timeout + 5)
    cookies = _read_cookie_jar(jar)
    if not cookies:
        UI.warn("auto-login: no session cookie returned — continuing unauthenticated")
        return False
    cookie_hdr = "; ".join(f"{k}={v}" for k, v in cookies.items())
    config.set("_cookie", cookie_hdr)
    root = target.web_services[0].url if target.web_services else action
    _s, _h, vbody, _r = _curl_full(root, config, runner, "login_verify")
    if re.search(r"log ?out|sign ?out|my account|my orders|dashboard", vbody or "", re.I):
        UI.ok(f"authenticated — session captured ({', '.join(cookies)})")
    else:
        UI.warn("auto-login: session set but couldn't confirm it (creds may be wrong)")
    return True




# --- Testing: CORS ----------------------------------------------------------



# --- Testing: auth surface --------------------------------------------------







# --- Testing: CRLF / header injection --------------------------------------



# --- Testing: Host header injection ----------------------------------------



# --- Enumeration: sensitive files / VCS exposure ---------------------------





WORDLIST_PHASES = {
    "content": ("content discovery", "gobuster", "wordlists.content"),
    "vhost": ("vhost fuzzing", "ffuf", "wordlists.vhost"),
}


# ════════════════════════════════════════════════════════════════════════
#  REPORT
# ════════════════════════════════════════════════════════════════════════

def _sec(title):
    return [title, "-" * len(title)]


def _r_endpoints(d):
    lines = _sec("ENDPOINTS")
    eps = d.get("endpoints", [])
    if not eps:
        lines.append("  none")
        return lines + [""]
    for u in eps:
        lines.append(f"  {u}")
    return lines + [""]


def _r_parameters(d):
    lines = _sec("PARAMETERS")
    ps = d.get("params", [])
    if not ps:
        lines.append("  none discovered")
        return lines + [""]
    for x in ps:
        lines.append(f"  [{x['where']}] {x['url']}  ->  {', '.join(x['params'])}")
    return lines + [""]



# ════════════════════════════════════════════════════════════════════════
#  VALIDATION ENGINE  ::  evidence graph + confidence scoring + injection
#  is reused from earlier phases instead of running isolated checks.
# ════════════════════════════════════════════════════════════════════════

import base64
import concurrent.futures as _cf
import enum
import math
import random
import statistics
import string
from collections import defaultdict as _defaultdict
from urllib.parse import parse_qsl


# ── evidence primitives ───────────────────────────────────────────────────

class NodeType(enum.Enum):
    FINDING = "finding"


class SignalStrength(enum.IntEnum):
    WEAK = 1
    MODERATE = 2
    STRONG = 3
    PROOF = 4


@dataclass(frozen=True)
class Signal:
    vuln: str
    technique: str
    independence: str
    strength: SignalStrength
    detail: str
    evidence: dict = field(default_factory=dict)


@dataclass
class _GNode:
    id: str
    type: NodeType
    attrs: dict = field(default_factory=dict)


class EvidenceGraph:
    """Small thread-safe store; findings accumulate signals."""

    def __init__(self):
        self._nodes = {}
        self._signals = _defaultdict(list)
        self._lock = threading.RLock()

    def upsert(self, node_id, ntype, **attrs):
        with self._lock:
            n = self._nodes.get(node_id)
            if n is None:
                n = _GNode(node_id, ntype, dict(attrs))
                self._nodes[node_id] = n
            else:
                n.attrs.update(attrs)
            return n

    def get(self, node_id):
        return self._nodes.get(node_id)

    def add_signal(self, finding_id, signal):
        with self._lock:
            self._signals[finding_id].append(signal)

    def signals(self, finding_id):
        with self._lock:
            return list(self._signals.get(finding_id, ()))

    def findings(self):
        with self._lock:
            return list(self._signals.keys())


# ── confidence engine ──────────────────────────────────────────────────────

class Verdict(enum.IntEnum):
    NONE = 0
    INFORMATIONAL = 1
    TENTATIVE = 2
    FIRM = 3
    CONFIRMED = 4


_CLASS_LR = {SignalStrength.WEAK: 3.0, SignalStrength.MODERATE: 9.0,
             SignalStrength.STRONG: 40.0, SignalStrength.PROOF: 600.0}
_PRIOR_ODDS = 1.0 / 200.0
_REPEAT_BASE, _REPEAT_CAP = 1.3, 2.0


@dataclass
class _Assessment:
    verdict: Verdict
    probability: float
    classes: int
    rationale: list


class ConfidenceEngine:
    def __init__(self, min_classes=2, thresholds=None):
        self.min_classes = min_classes
        self.thresholds = thresholds or {Verdict.CONFIRMED: 0.97, Verdict.FIRM: 0.85,
                                         Verdict.TENTATIVE: 0.55, Verdict.INFORMATIONAL: 0.0}

    def evaluate(self, signals):
        if not signals:
            return _Assessment(Verdict.NONE, 0.0, 0, ["no signals"])
        by_class = {}
        for s in signals:
            by_class.setdefault(s.independence, []).append(s)
        log_odds = math.log(_PRIOR_ODDS)
        rationale = []
        for cls, sigs in by_class.items():
            strongest = max(sigs, key=lambda x: x.strength)
            lr = _CLASS_LR[strongest.strength]
            lr *= min(_REPEAT_BASE ** min(len(sigs) - 1, 3), _REPEAT_CAP)
            log_odds += math.log(lr)
            rationale.append(f"{cls}: {strongest.strength.name.lower()} "
                             f"via {strongest.technique} (LR~{lr:.0f})")
        odds = math.exp(log_odds)
        prob = odds / (1.0 + odds)
        n = len(by_class)
        verdict = Verdict.NONE
        for v in (Verdict.CONFIRMED, Verdict.FIRM, Verdict.TENTATIVE, Verdict.INFORMATIONAL):
            if prob >= self.thresholds[v]:
                verdict = v
                break
        if n < self.min_classes and verdict > Verdict.TENTATIVE:
            rationale.append(f"clamped: {n} independent class(es), need {self.min_classes}")
            verdict = Verdict.TENTATIVE
        return _Assessment(verdict, prob, n, rationale)


# ── HTTP layer (pooling / dedup / rate-limit / retry-backoff / timeouts) ────

@dataclass
class HResponse:
    status: int
    headers: dict
    text: str
    elapsed: float
    url: str
    from_cache: bool = False


class Transport:
    def send(self, method, url, headers=None, body=None, timeout=None, follow=False):
        raise NotImplementedError


from urllib.request import HTTPRedirectHandler as _HTTPRedirectHandler


class _NoRedirect(_HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class _UrllibTransport(Transport):
    """Stdlib fallback (no extra dependency). Retries with backoff on transport
    errors; an HTTP error response (e.g. 500) is a valid result and returned."""

    def __init__(self, retries=2, backoff=0.5, read_timeout=15.0):
        self._retries, self._backoff, self._timeout = retries, backoff, read_timeout
        self._ctx = _ssl._create_unverified_context()

    def send(self, method, url, headers=None, body=None, timeout=None, follow=False):
        data = body.encode() if isinstance(body, str) else body
        last = None
        for attempt in range(self._retries + 1):
            start = time.time()
            try:
                req = Request(url, data=data, headers=headers or {}, method=method)
                handlers = [HTTPSHandler(context=self._ctx)]
                if not follow:
                    handlers.append(_NoRedirect())
                opener = build_opener(*handlers)
                with opener.open(req, timeout=timeout or self._timeout) as r:
                    text = r.read(500_000).decode("utf-8", "replace")
                    status = getattr(r, "status", None) or r.getcode()
                    return HResponse(status, dict(r.headers), text, time.time() - start, r.geturl())
            except Exception as exc:
                code = getattr(exc, "code", 0) or 0
                btext = ""
                try:
                    btext = exc.read().decode("utf-8", "replace")
                except Exception:
                    pass
                last = HResponse(code, dict(getattr(exc, "headers", {}) or {}), btext,
                                 time.time() - start, url)
                if code:
                    return last
                time.sleep(self._backoff * (2 ** attempt))
        return last or HResponse(0, {}, "", 0.0, url)


class RateLimiter:
    def __init__(self, max_concurrency=16, per_host_rps=12.0):
        self._sem = threading.BoundedSemaphore(max_concurrency)
        self._interval = (1.0 / per_host_rps) if per_host_rps > 0 else 0.0
        self._next = _defaultdict(float)
        self._lock = threading.Lock()

    def __enter__(self):
        self._sem.acquire()
        return self

    def __exit__(self, *a):
        self._sem.release()

    def throttle(self, host):
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            due = max(now, self._next[host])
            self._next[host] = due + self._interval
            wait = due - now
        if wait > 0:
            time.sleep(wait)


def _canonical_key(method, url, body=None):
    sp = urlsplit(url)
    q = urlencode(sorted(parse_qsl(sp.query, keep_blank_values=True)))
    b = ""
    if body:
        b = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
        try:
            b = urlencode(sorted(parse_qsl(b, keep_blank_values=True)))
        except Exception:
            pass
    return f"{method.upper()} {sp.scheme}://{sp.netloc}{sp.path}?{q}::{b}"


class HttpClient:
    def __init__(self, transport, rate_limiter=None, default_headers=None):
        self.t = transport
        self.rl = rate_limiter or RateLimiter()
        self.default_headers = dict(default_headers or {})
        self._cache = {}
        self._lock = threading.Lock()
        self.stats = _defaultdict(int)

    def request(self, method, url, headers=None, body=None, timeout=None, cache=True,
                replace_headers=False, follow=False):
        if replace_headers:
            h = dict(headers or {})
        else:
            h = dict(self.default_headers)
            if headers:
                h.update(headers)
        key = _canonical_key(method, url, body)
        if replace_headers:
            key += "::id=" + str(hash(frozenset(h.items())))
        if follow:
            key += "::follow"
        if cache:
            with self._lock:
                hit = self._cache.get(key)
            if hit is not None:
                self.stats["dedup_hits"] += 1
                return HResponse(hit.status, hit.headers, hit.text, hit.elapsed, hit.url, True)
        host = urlsplit(url).netloc
        self.rl.throttle(host)
        with self.rl:
            self.stats["sent"] += 1
            try:
                resp = self.t.send(method, url, headers=h, body=body, timeout=timeout, follow=follow)
            except Exception:
                resp = HResponse(0, {}, "", 0.0, url)
        if cache:
            with self._lock:
                self._cache[key] = resp
        return resp

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, body=None, **kw):
        return self.request("POST", url, body=body, **kw)


# ── injection point + module base ───────────────────────────────────────────

def _rand(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


@dataclass
class InjectionPoint:
    method: str
    url: str
    param: str
    params: dict = field(default_factory=dict)
    dynamic: bool = True
    tech: set = field(default_factory=set)
    content_type: str = ""
    body_is_xml: bool = False
    body: str = ""
    only_vulns: tuple = ()

    def finding_id(self, vuln):
        return f"{vuln}|{self.method} {self.url}|{self.param}"


def _send_with(http, ip, value, *, cache=True, headers=None, follow=False):
    params = dict(ip.params)
    params[ip.param] = value
    if ip.method.upper() == "GET":
        sp = urlsplit(ip.url)
        url = urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(params), ""))
        return http.get(url, headers=headers, cache=cache, follow=follow)
    hdrs = {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})}
    return http.post(ip.url, body=urlencode(params), headers=hdrs, cache=cache, follow=follow)




class _Module:
    name = ""
    vuln = ""
    _debug = False

    def requires(self, ip):
        return ip.dynamic

    def probe(self, http, ip):
        raise NotImplementedError


# ── SSTI ────────────────────────────────────────────────────────────────




# ── Command Injection ─────────────────────────────────────────────────────


# ── Path Traversal / LFI ──────────────────────────────────────────────────





_TRAV_PARAM_HINTS = ("file", "filename", "filepath", "path", "download", "dl",
                     "image", "img", "picture", "pic", "photo", "doc", "document",
                     "page", "template", "tpl", "view", "read", "load", "include",
                     "inc", "src", "source", "attachment", "media", "content",
                     "resource", "name", "f")

_TRAV_INJECT_NAMES = ("file", "path", "page", "filename", "download", "doc",
                      "view", "image")

_SSTI_INJECT_NAMES = ("name", "q", "search", "msg", "message", "input",
                      "title", "query")

_TRAV_FILE_ENDPOINT_RE = re.compile(
    r"(picture|image|img|photo|thumb|download|dl|/file|/files|getfile|view|"
    r"render|display|media|attachment|export|/read|load|/content|resource|"
    r"preview|/doc|/docs|/get)",
    re.I)




# ── XXE (XML endpoints only) ────────────────────────────────────────────


# ── IDOR (two-identity broken-access-control) ───────────────────────────
import difflib as _difflib















# ── orchestration: build injection points, run modules, score ──────────────

@dataclass
class _Finding:
    vuln: str
    where: str
    param: str
    method: str
    verdict: Verdict
    probability: float
    classes: int
    rationale: list
    signals: list


def _verdict_name(v):
    return {Verdict.NONE: "none", Verdict.INFORMATIONAL: "info", Verdict.TENTATIVE: "tentative",
            Verdict.FIRM: "firm", Verdict.CONFIRMED: "CONFIRMED"}.get(v, str(v))


def _ep_sig(ip):
    sp = urlsplit(ip.url)
    return f"{ip.method.upper()} {sp.scheme}://{sp.netloc}{sp.path}#{ip.param}"


def _tech_by_host(target):
    m = _defaultdict(set)
    for s in (target.results.get("technologies") or {}).get("services", []):
        h = urlsplit(s.get("url", "")).netloc
        for t in s.get("tech", []):
            m[h].add(str(t).lower())
    for s in (target.results.get("fingerprint") or {}).get("services", []):
        h = urlsplit(s.get("url", "")).netloc
        srv = (s.get("http", {}).get("headers", {}) or {}).get("server")
        if srv:
            m[h].add(srv.lower())
    return m


def _identity_headers(config, cookie_key, headers_key):
    """Build a request-header dict for one identity from a cookie + headers key."""
    h = {}
    for pair in (config.get(headers_key) or []):
        if ":" in pair:
            k, _, v = pair.partition(":")
            h[k.strip()] = v.strip()
    ck = config.get(cookie_key)
    if ck:
        h["Cookie"] = ck
    return h


def _make_http_client(config):
    rt = float(config.get("active.timeout", 10) or 10)
    transport = _UrllibTransport(read_timeout=rt)
    workers = max(2, min(int(config.get("threads", 40) or 40), 16))
    rl = RateLimiter(max_concurrency=workers, per_host_rps=float(config.get("_rps", 12) or 12))
    hdrs = {}
    for pair in auth_header_pairs(config):
        if ":" in pair:
            k, _, v = pair.partition(":")
            hdrs[k.strip()] = v.strip()
    return HttpClient(transport, rl, default_headers=hdrs)


def _validation_targets(target, config):
    pts, seen = [], set()
    techmap = _tech_by_host(target)

    def add(method, url, param, names, *, body="", ctype="", is_xml=False, only_vulns=()):
        ip = InjectionPoint(method=method.upper(), url=url, param=param,
                            params={n: "1" for n in names if n != param}, dynamic=True,
                            tech=techmap.get(urlsplit(url).netloc, set()),
                            content_type=ctype, body_is_xml=is_xml, body=body,
                            only_vulns=tuple(only_vulns))
        sig = _ep_sig(ip)
        if sig in seen:
            return
        seen.add(sig)
        pts.append(ip)

    for pe in getattr(target, "param_endpoints", []):
        url, names = pe.get("url"), pe.get("params", []) or []
        for p in names:
            add("GET", url, p, names)
    for su in getattr(target, "seed_urls", []):
        sp = urlsplit(su)
        if sp.query:
            names = list(parse_qs(sp.query, keep_blank_values=True).keys())
            base = urlunsplit((sp.scheme, sp.netloc, sp.path, "", ""))
            for p in names:
                add("GET", base, p, names)
    crawl = target.results.get("crawl") or {}
    for fm in crawl.get("forms", []) + list(getattr(target, "extra_forms", [])):
        action = fm.get("action")
        names = fm.get("inputs", []) or []
        method = (fm.get("method", "get") or "get").upper()
        for p in names:
            add(method, action, p, names)
    for xt in (config.get("_xml_targets") or []):
        add("POST", xt["url"], "xml", ["xml"], body=xt.get("body", ""),
            ctype=xt.get("content_type", "application/xml"), is_xml=True)

    # ---- speculative parameter guessing (autonomy without --url) ----
    # For endpoints discovered by crawl/content that expose no usable parameter
    known_paths = {(urlsplit(ip.url).netloc, urlsplit(ip.url).path) for ip in pts}
    discovered = set()
    content = target.results.get("content") or {}
    for e in content.get("services", []):
        base = e.get("url", "")
        for f in e.get("found", []):
            if (f.get("status") or 0) in (200, 301, 302, 401, 403):
                discovered.add(base.rstrip("/") + "/" + (f.get("path") or "").lstrip("/"))
    for pe in crawl.get("params", []):
        discovered.add(pe.get("url"))
    for u in crawl.get("urls", []):
        discovered.add(u)
    for pe in getattr(target, "param_endpoints", []):
        discovered.add(pe.get("url"))
    for su in getattr(target, "seed_urls", []):
        s = urlsplit(su)
        discovered.add(urlunsplit((s.scheme, s.netloc, s.path, "", "")))

    cap = int(config.get("active.max_endpoints", 60) or 60)
    trav_n = ssti_n = 0
    for u in sorted(x for x in discovered if x):
        sp = urlsplit(u)
        if (sp.netloc, sp.path) in known_paths:
            continue
        base = urlunsplit((sp.scheme, sp.netloc, sp.path, "", ""))
        if _TRAV_FILE_ENDPOINT_RE.search(sp.path) and trav_n < cap:
            for name in _TRAV_INJECT_NAMES:
                add("GET", base, name, [name], only_vulns=("traversal",))
            trav_n += 1
        if ssti_n < cap:
            for name in _SSTI_INJECT_NAMES:
                add("GET", base, name, [name], only_vulns=("ssti",))
            ssti_n += 1
    return pts


def _run_validation(target, config, runner):
    cached = getattr(target, "_validation", None)
    if cached is not None:
        return cached
    http = _make_http_client(config)
    points = _validation_targets(target, config)
    engine = ConfidenceEngine(min_classes=2)
    graph = EvidenceGraph()
    # injection modules self-register from their testing/*.py files
    modules = [cls() for cls in INJECTION_MODULES]
    if config.get("_verbose"):
        for m in modules:
            m._debug = True
    workers = 1 if config.get("_verbose") else max(2, min(int(config.get("threads", 40) or 40), 16))

    if not points:
        UI.warn("injection validation: no parameters/forms yet (run crawl first)")
    elif modules:
        UI.info(f"injection validation on {len(points)} point(s)")
        if config.get("_verbose"):
            for ip in points:
                tag = " [traversal-only]" if ip.only_vulns == ("traversal",) else ""
                UI.dim(f"      • {ip.method} {ip.url} [{ip.param}]{tag}")

    seen, jobs = set(), []
    for ip in points:
        if not ip.dynamic:
            continue
        for m in modules:
            if ip.only_vulns and m.vuln not in ip.only_vulns:
                continue
            if not m.requires(ip):
                continue
            key = (_ep_sig(ip), m.vuln)
            if key in seen:
                continue
            seen.add(key)
            jobs.append((m, ip))

    tested_counts = _defaultdict(int)
    for m, ip in jobs:
        tested_counts[m.vuln] += 1

    def work(m, ip):
        try:
            return m, ip, m.probe(http, ip)
        except Exception:
            return m, ip, []

    if jobs:
        with _cf.ThreadPoolExecutor(max_workers=workers) as pool:
            for fut in _cf.as_completed([pool.submit(work, m, ip) for m, ip in jobs]):
                m, ip, sigs = fut.result()
                if not sigs:
                    continue
                fid = ip.finding_id(m.vuln)
                for s in sigs:
                    graph.add_signal(fid, s)
                graph.upsert(fid, NodeType.FINDING, vuln=m.vuln, where=ip.url,
                             param=ip.param, method=ip.method)

    findings = []
    for fid in graph.findings():
        sigs = graph.signals(fid)
        a = engine.evaluate(sigs)
        n = graph.get(fid)
        findings.append(_Finding(n.attrs["vuln"], n.attrs["where"], n.attrs["param"],
                                 n.attrs.get("method", "GET"), a.verdict, a.probability,
                                 a.classes, a.rationale, sigs))
    out = {"findings": findings, "engine": engine, "http_stats": dict(http.stats),
           "tested": dict(tested_counts)}
    target._validation = out
    return out


def _finding_dict(f):
    return {"vuln": f.vuln, "url": f.where, "param": f.param, "method": f.method,
            "verdict": _verdict_name(f.verdict), "probability": f.probability,
            "classes": f.classes,
            "signals": [{"technique": s.technique, "detail": s.detail,
                         "independence": s.independence, "strength": int(s.strength),
                         "payload": (s.evidence or {}).get("payload", ""),
                         "req_url": (s.evidence or {}).get("url", "")}
                        for s in f.signals]}


def _vuln_phase(target, config, runner, vuln):
    data = _run_validation(target, config, runner)
    engine = data["engine"]
    conf, review = [], []
    for f in data["findings"]:
        if f.vuln != vuln:
            continue
        if f.verdict >= Verdict.CONFIRMED and f.classes >= engine.min_classes:
            conf.append(f)
        elif f.verdict >= Verdict.TENTATIVE:
            review.append(f)
    for f in conf:
        if vuln == "traversal":
            is_lfi = any(s.independence == "traversal.php_filter" for s in f.signals)
            head = "LFI (file inclusion)" if is_lfi else "PATH TRAVERSAL"
        else:
            head = vuln.upper()
        UI.ok(f"{head} [CONFIRMED] {f.method} {f.where} [{f.param}]  "
              f"p={f.probability:.3f} ({f.classes} independent checks)")
        for s in f.signals:
            UI.dim(f"      + {s.technique}: {s.detail}")
            ev = s.evidence or {}
            if ev.get("url"):
                UI.dim(f"          {ev['url']}")
            elif ev.get("payload"):
                UI.dim(f"          payload: {ev['payload']}")
        if vuln == "ssti":
            for ln in _ssti_exploit_lines([s.technique for s in f.signals]):
                UI.dim(f"      {ln}")
    for f in review:
        UI.warn(f"{vuln} [{_verdict_name(f.verdict)}] {f.method} {f.where} [{f.param}]  "
                f"p={f.probability:.3f} — needs manual verification")
    if not conf and not review:
        tested = (data.get("tested") or {}).get(vuln, 0)
        if tested:
            UI.dim(f"      no {vuln} findings ({tested} parameter(s) tested)")
        else:
            UI.dim(f"      no {vuln} findings")
    return {"confirmed": [_finding_dict(f) for f in conf],
            "review": [_finding_dict(f) for f in review], "errors": []}














# Ready-to-use PoC + RCE payloads per confirmed template engine (authorized
# testing only). Arithmetic alone can't always tell engines that share a syntax
# apart (e.g. {{ }} = Jinja2/Twig/Nunjucks), so ambiguous syntaxes list several
# candidate RCEs — pick the one matching the target's stack.




def _r_injection(title, d, classify=None, exploit=None):
    lines = _sec(title)
    conf, rev = d.get("confirmed", []), d.get("review", [])
    if not conf and not rev:
        note = d.get("errors", [])
        return lines + ["  " + (note[0] if note else "none found"), ""]
    for f in conf:
        tag = f"  ->  {classify(f)}" if classify else ""
        lines.append(f"  [CONFIRMED p={f['probability']:.3f}, {f['classes']} checks] "
                     f"{f['method']} {f['url']}  [{f['param']}]{tag}")
        for s in f["signals"]:
            lines.append(f"      + {s['technique']}: {s['detail']}")
            if s.get("req_url"):
                lines.append(f"          {s['req_url']}")
            elif s.get("payload"):
                lines.append(f"          payload: {s['payload']}")
        if exploit:
            for ln in exploit([s.get("technique", "") for s in f["signals"]]):
                lines.append(f"      {ln}")
    for f in rev:
        lines.append(f"  [review:{f['verdict']} p={f['probability']:.3f}] "
                     f"{f['method']} {f['url']}  [{f['param']}]  (manual verification)")
    return lines + [""]


INJECTION_MODULES = []

__all__ = [n for n in dir() if not n.startswith('__')]
