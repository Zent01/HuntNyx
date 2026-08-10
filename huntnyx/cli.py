from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403
from huntnyx.core.registry import *  # noqa: F401,F403
import subprocess


def build_report_text(target, phases_run):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    run = set(phases_run)
    out = ["=" * 60,
           f"HuntNyx report — {target.name}",
           f"generated: {ts}",
           f"phases:    {', '.join(phases_run)}",
           "web services: " + (", ".join(s.url for s in target.web_services) or "none"),
           "=" * 60, ""]

    def render(phase):
        data = target.results.get(phase)
        if data is None:
            return
        if phase in RENDERERS:
            out.extend(RENDERERS[phase](data))

    for stage_name, stage_phases in STAGES:
        phs = [p for p in stage_phases if p in run]
        if stage_name == "Testing" and "sqlmap" in run:
            phs = phs + ["sqlmap"]
        show_summaries = stage_name == "Enumeration" and ("crawl" in run or "arjun" in run)
        if not phs and not show_summaries:
            continue
        out.append("#" * 60)
        out.append(f"#  {_stage_title(stage_name)}")
        out.append("#" * 60)
        out.append("")
        for phase in phs:
            render(phase)
        if show_summaries:
            out.extend(SUMMARY_RENDER["endpoints"](_summarize_endpoints(target)))
            out.extend(SUMMARY_RENDER["parameters"](_summarize_parameters(target)))

    out.append("#" * 60)
    out.append(f"#  {_stage_title('Reporting')}")
    out.append("#" * 60)
    out.append(f"  {len(phases_run)} phases run — saved to this file.")
    return "\n".join(out)


def _status_color(code):
    c = int(code)
    if 200 <= c < 300:
        return UI.GREEN
    if 300 <= c < 400:
        return UI.CYAN
    if c in (401, 403):
        return UI.YELLOW
    if 500 <= c < 600:
        return UI.RED
    return UI.WHITE


_SEV_COLOR = {"critical": UI.RED, "high": UI.RED, "medium": UI.YELLOW,
              "low": UI.CYAN, "info": UI.GREY, "unknown": UI.GREY}
_SEV_RE = re.compile(r"\[(critical|high|medium|low|info|unknown)\]")


def print_report_colored(text):
    """Print the plaintext report to the terminal with neon coloring."""
    if not UI.enabled:
        print(text)
        return
    status_re = re.compile(r"\[(\d{3})\]")
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        s = ln.strip()
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
        is_underline = bool(nxt) and set(nxt) <= {"-"} and len(nxt) >= 3
        if s and set(s) <= {"="}:
            print(UI.c(ln, UI.PURPLE, bold=True))
        elif s and set(s) <= {"#"}:
            print(UI.c(ln, UI.PINK, bold=True))
        elif ln.startswith("#  "):
            print(UI.c(ln, UI.PINK, bold=True))
        elif ln.startswith("HuntNyx report"):
            print(UI.c(ln, UI.PINK, bold=True))
        elif s and set(s) <= {"-"}:
            print(UI.c(ln, UI.PURPLE))
        elif not ln.startswith(" ") and s and (is_underline or (s == s.upper() and re.search(r"[A-Z]", s))):
            print(UI.c(ln, UI.CYAN, bold=True))
        elif not ln.startswith(" ") and ":" in ln:
            k, _, v = ln.partition(":")
            print(UI.c(k + ":", UI.PURPLE, bold=True) + UI.c(v, UI.WHITE))
        else:
            line = status_re.sub(lambda m: UI.c(m.group(0), _status_color(m.group(1)), bold=True), ln)
            line = _SEV_RE.sub(lambda m: UI.c(m.group(0), _SEV_COLOR.get(m.group(1), UI.WHITE), bold=True), line)
            if "/etc/hosts" in line:
                line = UI.c(line, UI.GREEN)
            elif line.strip().startswith("!"):
                line = UI.c(line, UI.YELLOW)
            print(line)


# ════════════════════════════════════════════════════════════════════════
#  INTERACTIVE
# ════════════════════════════════════════════════════════════════════════

def prompt_wordlist(phase, config):
    label, tool, key = WORDLIST_PHASES[phase]
    default = config.get(key)
    while True:
        UI.info(f"wordlist for {UI.c(tool, UI.PINK)} ({label})")
        val = UI.ask("  Path", default)
        if not val:
            if not sys.stdin.isatty():
                config.set(key, "")
                return
            # Enter ή y = skip και πήγαινε στο επόμενο wordlist
            ans = UI.ask_warn("Are you sure to skip ?", "Enter=skip, n=retry").lower()
            if ans in ("", "y", "yes"):
                config.set(key, "")
                return  # ← Βγαίνει από τη συνάρτηση, ο wizard προχωράει στο επόμενο phase
            continue  # ← n ή οτιδήποτε άλλο = ξαναρώτα για το ΙΔΙΟ wordlist
        expanded = os.path.expanduser(val)
        if os.path.isfile(expanded):
            config.set(key, expanded)
            UI.ok(f"using {expanded}")
            return  # ← Βρέθηκε αρχείο, πήγαινε στο επόμενο phase
        UI.err(f"file not found: {expanded}")
        if not sys.stdin.isatty():
            config.set(key, expanded)
            return
        if not UI.ask_yes_no("  Try another path?", default=True, color=UI.RED):
            UI.warn(f"skipping wordlist for {tool} - file not found")
            config.set(key, "")
            return  # ← Παράλειψη, πήγαινε στο επόμενο phase
        # ← y/Enter στο "Try another path?" = ξαναρώτα για το ΙΔΙΟ wordlist


def _slug(target):
    s = re.sub(r"^\w+://", "", (target or "").strip()).strip("/")
    s = re.sub(r"[^A-Za-z0-9._-]", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "target"


def _normalize_outfile(name, target):
    name = (name or "").strip() or f"{_slug(target)}_enum.txt"
    if not name.lower().endswith(".txt"):
        name += ".txt"
    return name


def _target_scheme_ok(raw):
    """Accept a valid IP address (optionally with :port), or an http(s):// URL.
    Anything else is rejected. Returns (ok, error)."""
    s = (raw or "").strip()
    if s:
        host = s
        if host.startswith("[") and "]" in host:
            host = host[1:host.index("]")]
        elif host.count(":") == 1:
            host = host.rsplit(":", 1)[0]
        try:
            ipaddress.ip_address(host)
            return True, ""
        except ValueError:
            pass
        low = s.lower()
        for pre in ("https://", "http://"):
            if low.startswith(pre) and len(s) > len(pre):
                return True, ""
    return False, "Invalid IP address or URL !"


def prompt_auth(config):
    if not config.get("_cookie"):
        ck = UI.ask("Session cookie (e.g. 'PHPSESSID=abc'; blank if none)")
        if ck:
            config.set("_cookie", ck)
    if not config.get("_headers"):
        hd = UI.ask("Extra header (e.g. 'Authorization: Bearer ...'; blank if none)")
        if hd:
            config.set("_headers", [hd])



def _target_as_url(target):
    t = (target or "").strip()
    return (t if re.match(r"^\w+://", t) else "http://" + t).rstrip("/")


def prompt_curl_preview(target, config):
    """Optional: fetch the target with curl and show the response for triage."""
    if not UI.ask_yes_no("Preview the target with curl first?", default=False):
        return
    url = _target_as_url(target)
    timeout = config.get("timeouts.curl", 15)
    cmd = ["curl", "-sS", "-i", "-k", "-L", "--max-time", str(timeout),
           *auth_curl(config), url]
    UI.info(f"curl {UI.c(url, UI.WHITE)}")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout + 5).stdout
    except FileNotFoundError:
        UI.err("curl not found on PATH")
        return
    except subprocess.TimeoutExpired:
        UI.err("curl timed out")
        return
    if not out.strip():
        UI.warn("empty response")
        return
    sep = "\r\n\r\n" if "\r\n\r\n" in out else "\n\n"
    head, _, body = out.partition(sep)
    for ln in head.splitlines():
        UI.dim("      " + ln)
    body_lines = [l for l in body.splitlines() if l.strip()][:15]
    if body_lines:
        UI.dim("      --- body (first lines) ---")
        for ln in body_lines:
            UI.dim("      " + ln[:200])


def prompt_cewl_wordlist(target, phases, config):
    """Optional: build a custom wordlist from the target with cewl and wire it
    into content/vhost fuzzing. Returns the set of phase keys it satisfied."""
    done = set()
    if not any(p in WORDLIST_PHASES for p in phases):
        return done
    if not shutil.which("cewl"):
        UI.dim("      cewl not installed - skipping custom wordlist")
        return done
    if not UI.ask_yes_no("Build a custom wordlist from the target with cewl?",
                         default=False):
        return done
    url = _target_as_url(target)
    depth = UI.ask("cewl crawl depth", "2")
    minlen = UI.ask("minimum word length", "4")
    outfile = os.path.abspath(f"{_slug(target)}_cewl.txt")
    timeout = config.get("timeouts.default", 300)
    UI.info(f"cewl -> {UI.c(outfile, UI.WHITE)}  (depth={depth}, min={minlen})")
    try:
        subprocess.run(["cewl", "-d", str(depth), "-m", str(minlen),
                        "-w", outfile, url],
                       capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        UI.err("cewl not found on PATH")
        return done
    except subprocess.TimeoutExpired:
        UI.err("cewl timed out")
        return done
    try:
        n = sum(1 for ln in open(outfile, encoding="utf-8", errors="ignore") if ln.strip())
    except OSError:
        n = 0
    if n == 0:
        UI.warn("cewl produced no words - keeping existing wordlist")
        return done
    UI.ok(f"generated {n} words -> {outfile}")
    if "content" in phases:
        config.set("wordlists.content", outfile)
        UI.ok("using cewl wordlist for content discovery")
        done.add("content")
    if "vhost" in phases and UI.ask_yes_no(
            "Use the cewl wordlist for vhost fuzzing too?", default=False):
        config.set("wordlists.vhost", outfile)
        UI.ok("using cewl wordlist for vhost fuzzing")
        done.add("vhost")
    return done


def prompt_curl(target_name, config):
    """Optional: preview the target's raw HTTP response before scanning."""
    if not UI.ask_yes_no("Preview the target with curl first?", default=False):
        return
    url = target_name if re.match(r"^https?://", target_name) else "http://" + target_name.rstrip("/")
    timeout = str(config.get("timeouts.curl", 15))
    cmd = ["curl", "-s", "-i", "-k", "--max-time", timeout, *auth_curl(config), url]
    UI.info(f"curl -i {url}")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=int(timeout) + 5)
    except FileNotFoundError:
        UI.err("curl not found on PATH")
        return
    except subprocess.TimeoutExpired:
        UI.err("curl timed out")
        return
    out = res.stdout or ""
    if not out.strip():
        err = (res.stderr or "").strip()
        UI.warn("empty response" + (f" ({err[:120]})" if err else ""))
        return
    sep = "\r\n\r\n" if "\r\n\r\n" in out else "\n\n"
    head, _, body = out.partition(sep)
    for ln in head.splitlines():
        print("    " + UI.c(ln, UI.CYAN))
    body = body.strip()
    if body:
        print("    " + UI.c("--- body (first 800 bytes) ---", UI.GREY))
        for ln in body[:800].splitlines()[:20]:
            print("    " + ln)
        if len(body) > 800:
            print("    " + UI.c("... (truncated)", UI.GREY))


def prompt_cewl(target_name, config, phases):
    """Optional: spider the site with cewl and use the result as a wordlist."""
    if not any(p in phases for p in ("content", "vhost")):
        return
    if not shutil.which("cewl"):
        return  # silently skip when cewl isn't installed
    if not UI.ask_yes_no("Build a custom wordlist from the site with cewl?", default=False):
        return
    url = target_name if re.match(r"^https?://", target_name) else "http://" + target_name.rstrip("/")
    depth = (UI.ask("  cewl crawl depth", "2") or "2").strip()
    minlen = (UI.ask("  min word length", "4") or "4").strip()
    out = os.path.abspath(f"{_slug(target_name)}_cewl.txt")
    cmd = ["cewl", "-d", depth, "-m", minlen, "-w", out, url]
    cookie = config.get("_cookie")
    if cookie:
        cmd += ["--cookie_string", cookie]
    UI.info("running cewl (this can take a moment) ...")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        UI.err("cewl not found on PATH")
        return
    except subprocess.TimeoutExpired:
        UI.err("cewl timed out (>5 min) — skipping")
        return
    if not (os.path.isfile(out) and os.path.getsize(out) > 0):
        UI.warn("cewl produced no wordlist — keeping existing choice")
        return
    with open(out, encoding="utf-8", errors="ignore") as fh:
        n = sum(1 for _ in fh)
    UI.ok(f"cewl wordlist: {out}  ({n} words)")
    if "content" in phases and UI.ask_yes_no("  Use it for directory (content) fuzzing?", default=True):
        config.set("wordlists.content", out)
    if "vhost" in phases and UI.ask_yes_no("  Use it for vhost fuzzing?", default=False):
        config.set("wordlists.vhost", out)


def interactive_wizard(config):
    UI.phase("interactive setup")
    target = ""
    while not target:
        entry = UI.ask("Target IP / URL")
        if not entry:
            continue
        ok, err = _target_scheme_ok(entry)
        if not ok:
            UI.err(err)
            continue
        target = entry

    # Ορισμός phases και ερώτηση για sqlmap με default = No
    phases = list(PHASE_ORDER)
    print()
    want_sqlmap = UI.ask_yes_no("Run sqlmap on discovered parameters?", default=False)
    
    if any(p in phases for p in ACTIVE_PHASES) and "crawl" not in phases:
        insert_at = phases.index("content") + 1 if "content" in phases else 0
        phases.insert(insert_at, "crawl")
    if want_sqlmap:
        phases = phases + ["sqlmap"]

    # ΑΦΑΙΡΟΥΜΕ την ερώτηση για domain από εδώ (μεταφέρεται παρακάτω)

    UI.phase("authentication")
    prompt_auth(config)

    UI.phase("recon")
    prompt_curl_preview(target, config)
    cewl_done = prompt_cewl_wordlist(target, phases, config)

    UI.phase("wordlists")
    outfile = _normalize_outfile(None, target)
    for phase in phases:
        if phase in WORDLIST_PHASES and phase not in cewl_done:
            # Ρωτάει για domain ακριβώς πριν το vhost wordlist
            if phase == "vhost" and not config.get("_domain"):
                dom = UI.ask("Domain for VHost fuzzing (blank to skip VHost enumeration)")
                if dom:
                    config.set("_domain", dom)
                else:
                    UI.warn("vhost fuzzing skipped (no domain provided)")
                    continue  # Προσπερνάει το vhost wordlist
            prompt_wordlist(phase, config)

    UI.phase("summary")
    UI.kv("target", target)
    UI.kv("stages", ", ".join(dict.fromkeys(STAGE_OF.get(p, "?") for p in phases)))
    UI.kv("phases", ", ".join(phases))
    UI.kv("report", outfile)
    return target, phases, outfile

# ════════════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════════════

def print_help():
    C = UI.c
    FW = 22

    def hdr(t):
        return C(t, UI.PINK, bold=True)

    def row(flag, desc, tool=""):
        left = C(flag.ljust(FW), UI.CYAN, bold=True)
        mid = C(desc, UI.WHITE)
        right = ("  " + C(f"({tool})", UI.PURPLE)) if tool else ""
        return f"    {left}{mid}{right}"

    UI.banner()
    print(hdr("  HuntNyx") + C("  — web-app enumeration & testing pipeline (TryHackMe PT1)", UI.GREY))
    print()
    print(hdr("  USAGE"))
    print(row("pt1enum.py [target] [flags] [options]", ""))
    print(f"    {C('pt1enum.py'.ljust(FW), UI.CYAN, bold=True)}"
          + C("(no target) -> interactive wizard", UI.GREY))
    print()
    print(hdr("  TARGET"))
    print(row("target", "IP / host / URL - e.g. http://site.thm/?id=1"))
    print()
    print(hdr("  STAGES") + C("  (run a whole stage)", UI.GREY))
    for name, _ in STAGES:
        print(row(f"--{name.lower()}", name, STAGE_TOOLS.get(name, "")))
    print(row("--all", "run the full flow (default when no flags)"))
    print()
    print(hdr("  PHASES") + C("  (pick individual steps)", UI.GREY))
    for name, phs in STAGES:
        print("    " + C(name, UI.GREEN, bold=True))
        for key in phs:
            tool = ", ".join(PHASE_TOOL.get(key, []))
            print("  " + row(f"--{key}", PHASE_LABEL.get(key, key), tool))
        if name == "Testing":
            print("  " + row("--sqlmap", "SQLMap auto-confirm (opt-in)", "sqlmap"))
    print()
    print(hdr("  OPTIONS"))
    for flag, desc in [
        ("-o, --output FILE", "report .txt (default <target>_enum.txt)"),
        ("-c, --config FILE", "JSON config file"),
        ("--ports-list P", "skip nmap; seed web ports e.g. 80,443,8080"),
        ("--domain D", "domain for vhost fuzzing (else derived from target)"),
        ("--cookie C", "session cookie, e.g. 'PHPSESSID=...'"),
        ("--header H", "extra header 'Name: value' (repeatable)"),
        ("--login-data D", "credentials for auto-login (authenticated scan)"),
        ("--login-url U", "login page for auto-login (authenticated scan)"),
        ("--threads N", "concurrency for fuzzers"),
        ("-r, --request FILE", "read a raw HTTP request (Burp-style) and test it"),
        ("--url URL", "extra URL with params to test (repeatable)"),
        ("--urls FILE", "file of URLs to test (one per line)"),
        ("--add-hosts", "write found vhosts to /etc/hosts and scan them (root)"),
        ("-y, --yes", "non-interactive: use config, no prompts"),
        ("--no-color", "disable ANSI colors"),
        ("--check-deps", "list tool availability and exit"),
        ("-v, --verbose", "verbose output"),
        ("-q, --quiet", "quiet output"),
        ("-h, --help", "show this help and exit"),
    ]:
        print(row(flag, desc))
    print()
    print(hdr("  EXAMPLES"))
    for ex in [
        "pt1enum.py http://site.thm --all",
        "pt1enum.py http://site.thm/?id=1 --testing --cookie 'session=...'",
        "sudo pt1enum.py http://site.thm --enumeration --add-hosts",
        "pt1enum.py 10.10.10.5 --ports-list 80,8080 --discovery",
        "pt1enum.py --check-deps",
    ]:
        print("    " + C("$ ", UI.GREY) + C(ex, UI.WHITE))
    print()


def parse_http_request(text):
    text = text.replace("\r\n", "\n")
    if "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        head, body = text, ""
    lines = [l for l in head.split("\n")]
    if not lines or len(lines[0].split()) < 2:
        raise ValueError("not a valid HTTP request (missing request line)")
    method, path = lines[0].split()[0].upper(), lines[0].split()[1]

    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()

    host = headers.get("host", "").strip()
    scheme = "http"
    for h in ("origin", "referer"):
        if headers.get(h, "").startswith("https://"):
            scheme = "https"
    sp = urlsplit(path if "://" in path else scheme + "://" + host + path)
    clean_path = sp.path or "/"
    query = sp.query
    base = f"{scheme}://{host}{clean_path}"

    ct = headers.get("content-type", "")
    body_fields = []
    if body.strip():
        if "multipart/form-data" in ct:
            m = re.search(r"boundary=(.+)", ct)
            bnd = m.group(1).strip().strip('"') if m else None
            if bnd:
                for part in body.split("--" + bnd):
                    nm = re.search(r'name="([^"]+)"', part)
                    if nm:
                        body_fields.append(nm.group(1))
        elif "application/json" in ct:
            try:
                obj = json.loads(body)
                if isinstance(obj, dict):
                    body_fields = list(obj.keys())
            except Exception:
                pass
        else:
            body_fields = list(parse_qs(body, keep_blank_values=True).keys())

    keep = []
    for k, v in headers.items():
        if k in ("authorization",) or k.startswith("x-") or "csrf" in k or "token" in k:
            keep.append(f"{k.title()}: {v}")

    return {
        "method": method, "scheme": scheme, "host": host, "path": clean_path,
        "url": base, "query": query, "body_fields": body_fields,
        "cookie": headers.get("cookie", ""), "headers": keep,
        "content_type": ct, "raw_body": body,
    }


def _looks_like_xml(content_type, body, query=""):
    """Decide whether a raw request body is XML, so XXE runs even when the
    request omits a Content-Type header. Real-world captures (and apps that
    switch on a ?xml query flag, like nahamstore's /product/1?xml) frequently
    send an XML body with no XML Content-Type at all."""
    if "xml" in (content_type or "").lower():
        return True
    b = (body or "").lstrip()
    if b.startswith("<?xml"):
        return True
    # a markup body plus an explicit ?xml switch in the query string
    if b.startswith("<") and re.search(r"(?:^|&)xml(?:$|=|&)", query or ""):
        return True
    return False


def build_parser():
    p = argparse.ArgumentParser(prog="pt1enum.py", add_help=False,
                                description="HuntNyx — web-app enumeration wrapper (recon only).",
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-h", "--help", action="store_true", help="show colorized help and exit")
    p.add_argument("target", nargs="?", help="target IP or hostname")
    ph = p.add_argument_group("phase selection (default: full flow)")
    for name in PHASE_ORDER:
        ph.add_argument(f"--{name}", action="store_true")
    ph.add_argument("--all", action="store_true", help="run the full flow (default)")
    st = p.add_argument_group("stage selection (run a whole stage)")
    st.add_argument("--discovery", action="store_true", help="Discovery stage")
    st.add_argument("--enumeration", action="store_true", help="Enumeration stage")
    st.add_argument("--testing", action="store_true", help="Testing stage")
    act = p.add_argument_group("heavy / opt-in")
    act.add_argument("--sqlmap", action="store_true",
                     help="auto-run sqlmap on discovered GET params / POST forms (confirmation)")
    opt = p.add_argument_group("options")
    opt.add_argument("-o", "--output", metavar="FILE",
                     help="report .txt file (default: <target>_enum.txt)")
    opt.add_argument("-c", "--config", default="config.json", metavar="FILE")
    opt.add_argument("--ports-list", metavar="P", help="skip nmap; e.g. 80,443,8080")
    opt.add_argument("--domain", metavar="D", help="domain for vhost fuzzing")
    opt.add_argument("--cookie", metavar="C", help="session cookie, e.g. 'PHPSESSID=...'")
    opt.add_argument("--header", metavar="H", action="append", default=[],
                     help="extra header 'Name: value' (repeatable)")
    opt.add_argument("--login-data", metavar="D",
                     help="credentials for auto-login (authenticated scan), "
                          "e.g. 'login_email=a@b.c&login_password=x'")
    opt.add_argument("--login-url", metavar="U",
                     help="explicit login page URL for auto-login (else auto-detected)")
    opt.add_argument("--threads", type=int, metavar="N")
    opt.add_argument("-y", "--yes", action="store_true",
                     help="non-interactive: use config wordlists, no prompts")
    opt.add_argument("--no-color", action="store_true")
    opt.add_argument("-r", "--request", metavar="FILE",
                     help="read a raw HTTP request (Burp-style) and test its target/params")
    opt.add_argument("--url", action="append", metavar="URL", default=[],
                     help="extra URL with params to test (repeatable), e.g. '.../?file='")
    opt.add_argument("--urls", metavar="FILE",
                     help="file with URLs to test (one per line)")
    opt.add_argument("--check-deps", action="store_true")
    opt.add_argument("--add-hosts", action="store_true",
                     help="write discovered vhosts to /etc/hosts (needs root) and scan them this run")
    opt.add_argument("-v", "--verbose", action="store_true")
    opt.add_argument("-q", "--quiet", action="store_true")
    return p


def _ensure_tool(label, tools):
    while True:
        if any(shutil.which(t) for t in tools):
            return True
        if not sys.stdin.isatty():
            return False
        arrow = UI.c("▶", UI.PINK, bold=True)
        name = UI.c(f"'{label}'", UI.PINK, bold=True)
        msg = UI.c(" not installed — ", UI.YELLOW)
        opts = (UI.c("[Enter]", UI.CYAN, bold=True) + UI.c("=retry after installing, ", UI.GREY)
                + UI.c("path", UI.CYAN, bold=True) + UI.c("=use that binary, ", UI.GREY)
                + UI.c("s", UI.CYAN, bold=True) + UI.c("=skip", UI.GREY))
        ans = UI._input(f"{arrow} {name}{msg}{opts} ")
        if ans.lower() in ("s", "skip", "n", "no"):
            return False
        if ans and os.path.exists(ans):
            d = ans if os.path.isdir(ans) else (os.path.dirname(ans) or ".")
            os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")


def resolve_tools(phases, args):
    kept = []
    for phase in phases:
        tools = PHASE_TOOL.get(phase)
        if not tools or any(shutil.which(t) for t in tools):
            kept.append(phase)
            continue
        label = " / ".join(tools)
        pretty = PHASE_LABEL.get(phase, phase)
        if args.yes or args.quiet or not sys.stdin.isatty():
            UI.warn(f"{label} not found — skipping {pretty}")
            continue
        if _ensure_tool(label, tools):
            kept.append(phase)
        else:
            UI.warn(f"skipping {pretty}")
    return kept


def selected_phases(args):
    stage_sel = []
    for name, phs in STAGES:
        if getattr(args, name.lower(), False):
            stage_sel += phs
    indiv = [p for p in PHASE_ORDER if getattr(args, p, False)]
    chosen = list(dict.fromkeys(stage_sel + indiv))
    if args.all or not chosen:
        recon = list(PHASE_ORDER)
    else:
        recon = [p for p in PHASE_ORDER if p in set(chosen)]
    needs_disc = any(p in recon for p in ACTIVE_PHASES)
    if needs_disc:
        for helper in ("content", "arjun", "crawl"):
            if helper not in recon:
                recon.append(helper)
    ordered = [p for p in PHASE_ORDER if p in set(recon)]
    full_flow = args.all or not chosen
    run_sqlmap = getattr(args, "sqlmap", False) or getattr(args, "testing", False) or full_flow
    tail = ["sqlmap"] if run_sqlmap else []
    return ordered + tail


def main(argv=None):
    args = build_parser().parse_args(argv)
    UI.init(force_no_color=args.no_color or args.quiet)
    if args.help:
        print_help()
        return 0
    if not args.quiet:
        UI.banner()

    if args.check_deps:
        print_dep_report(dep_check())
        return 0

    config = Config.load(args.config)
    config.apply_overrides(threads=args.threads)
    if args.domain:
        config.set("_domain", args.domain)
    if args.cookie:
        config.set("_cookie", args.cookie)
    if args.header:
        config.set("_headers", list(args.header))
    if getattr(args, "login_data", None):
        config.set("_login_data", args.login_data)
    if getattr(args, "login_url", None):
        config.set("_login_url", args.login_url)
    config.set("_add_hosts", bool(getattr(args, "add_hosts", False)))
    config.set("_yes", bool(args.yes))
    config.set("_verbose", bool(args.verbose))

    req = None
    if args.request:
        try:
            with open(args.request, encoding="utf-8", errors="ignore") as fh:
                req = parse_http_request(fh.read())
        except Exception as exc:
            UI.err(f"could not parse request file: {exc}")
            return 2
        if not args.cookie and req["cookie"]:
            config.set("_cookie", req["cookie"])
        if not args.header and req["headers"]:
            config.set("_headers", req["headers"])
        if not args.domain and req["host"]:
            config.set("_domain", req["host"].split(":")[0])
        config.set("_request_file", os.path.abspath(args.request))
        if (req.get("raw_body") or "").strip() and _looks_like_xml(
                req.get("content_type"), req.get("raw_body"), req.get("query")):
            # keep the query string (e.g. ?xml) — some apps only parse the body
            # as XML when that switch is present (nahamstore /product/1?xml)
            xml_url = req["url"] + ("?" + req["query"] if req.get("query") else "")
            config.set("_xml_targets", [{"url": xml_url, "body": req["raw_body"],
                                         "content_type": req.get("content_type") or "application/xml"}])
        args.target = req["url"] + ("?" + req["query"] if req["query"] else "")
        UI.info(f"loaded request: {req['method']} {req['url']}  "
                + (f"fields: {', '.join(req['body_fields'])}" if req["body_fields"] else "(no body fields)"))

    interacted = False
    if not args.target:
        if args.yes:
            UI.err("target required with -y (or run without -y for the wizard)")
            return 2
        target_name, phases, outfile = interactive_wizard(config)
        interacted = True
    else:
        target_name = args.target
        phases = selected_phases(args)
        if args.ports_list and "ports" in phases:
            phases = [p for p in phases if p != "ports"]
        outfile = _normalize_outfile(args.output, target_name)
        if not args.yes:
            if "vhost" in phases and not config.get("_domain"):
                dom = UI.ask("Domain for vhost fuzzing (blank to skip vhost)")
                interacted = True
                if dom:
                    config.set("_domain", dom)
                else:
                    phases = [p for p in phases if p != "vhost"]
            if not config.get("_cookie") or not config.get("_headers"):
                prompt_auth(config)
                interacted = True
            prompt_curl_preview(target_name, config)
            cewl_done = prompt_cewl_wordlist(target_name, phases, config)
            interacted = True
            for phase in phases:
                if phase in WORDLIST_PHASES and phase not in cewl_done:
                    prompt_wordlist(phase, config)
                    interacted = True

    if interacted and not args.quiet:
        UI.clear()
        UI.banner()

    if not args.quiet:
        print_dep_report(dep_check(required_phases=set(phases)))

    phases = resolve_tools(phases, args)
    dropped_wl = [p for p in phases
                  if p in WORDLIST_PHASES and not config.get(WORDLIST_PHASES[p][2])]
    if dropped_wl:
        phases = [p for p in phases if p not in dropped_wl]
    if not phases:
        UI.err("no runnable phases left")
        return 1

    workdir = tempfile.mkdtemp(prefix="huntnyx_")
    target = Target(target_name, workdir)
    target.prepare()
    if args.ports_list:
        target.seed_from_ports_list(args.ports_list, config.get("https_ports", []))
    extra_urls = list(getattr(args, "url", []) or [])
    if getattr(args, "urls", None):
        try:
            with open(args.urls, encoding="utf-8", errors="ignore") as fh:
                extra_urls += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except Exception as exc:
            UI.warn(f"could not read --urls file: {exc}")
    for extra_url in extra_urls:
        if extra_url not in target.seed_urls:
            target.seed_urls.append(extra_url)
        sp = urlsplit(extra_url)
        if sp.scheme in ("http", "https") and sp.hostname:
            prt = sp.port or (443 if sp.scheme == "https" else 80)
            target.add_web_service(prt, sp.scheme, host=sp.hostname)
    if req and req["method"] == "POST" and req["body_fields"]:
        target.extra_forms.append({"action": req["url"], "method": "post",
                                   "inputs": req["body_fields"]})

    runner = Runner(log_dir=target.raw_dir, verbose=args.verbose, quiet=args.quiet,
                    default_timeout=config.get("timeouts.default", 300))

    if config.get("_login_data"):
        UI.phase("auto-login")
        _auto_login(target, config, runner)

    UI.phase("run")
    UI.kv("target", target.name)
    UI.kv("phases", ", ".join(phases))
    if target.web_services:
        UI.kv("seeded", ", ".join(s.url for s in target.web_services))

    UI.phase("files")
    cfg_ok = os.path.isfile(args.config)
    UI.kv("config", args.config if cfg_ok else "built-in defaults (no config.json)")
    if "content" in phases:
        _show_file("content wordlist", config.get("wordlists.content"))
    if "vhost" in phases:
        _show_file("vhost wordlist", config.get("wordlists.vhost"))
    if any(p in phases for p in ("sqlmap",) + tuple(ACTIVE_PHASES)):
        UI.dim("      (scan intermediates use a temp dir, removed on exit)")

    current_stage = None
    for phase in phases:
        st = STAGE_OF.get(phase) or ("Testing" if phase == "sqlmap" else "")
        if st and st != current_stage:
            current_stage = st
            tools = STAGE_TOOLS.get(st, "")
            title = UI.c(st.upper(), UI.PINK, bold=True)
            if tools:
                title += UI.c(f"  ({tools})", UI.GREY)
            print()
            print(UI.c("═" * 52, UI.PURPLE, bold=True))
            print("  " + title)
            print(UI.c("═" * 52, UI.PURPLE, bold=True))
        UI.phase(PHASE_LABEL.get(phase, phase))
        try:
            target.results[phase] = PHASES[phase](target, config, runner)
        except Exception as exc:
            target.results[phase] = {"errors": [f"phase crashed: {exc}"]}
            UI.err(f"{phase} crashed: {exc}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    report_text = build_report_text(target, phases)
    try:
        Path(outfile).write_text(report_text, encoding="utf-8")
        saved = True
    except Exception as exc:
        saved = False
        UI.err(f"could not write {outfile}: {exc}")

    if saved:
        UI.phase("report")
        UI.ok(f"saved report -> {UI.c(outfile, UI.GREEN, bold=True)}")

    shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        UI.err("interrupted")
        raise SystemExit(130)
