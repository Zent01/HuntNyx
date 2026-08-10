# HuntNyx

```
  ██╗  ██╗  ██╗   ██╗  ███╗   ██╗  ████████╗    ╲   ╱     ███╗   ██╗  ██╗   ██╗  ██╗  ██╗
  ██║  ██║  ██║   ██║  ████╗  ██║  ╚══██╔══╝    ╲╲ ╱╱     ████╗  ██║  ╚██╗ ██╔╝  ╚██╗██╔╝
  ███████║  ██║   ██║  ██╔██╗ ██║     ██║       ▟▔▔▔▙     ██╔██╗ ██║   ╚████╔╝    ╚███╔╝
  ██╔══██║  ██║   ██║  ██║╚██╗██║     ██║       ▜◣ ◢▛     ██║╚██╗██║    ╚██╔╝     ██╔██╗
  ██║  ██║  ╚██████╔╝  ██║ ╚████║     ██║        ╲▽╱      ██║ ╚████║     ██║     ██╔╝ ██╗
  ╚═╝  ╚═╝   ╚═════╝   ╚═╝  ╚═══╝     ╚═╝         ╹       ╚═╝  ╚═══╝     ╚═╝     ╚═╝  ╚═╝
```

**A web-application enumeration & testing pipeline that orchestrates the tools you already use.**

HuntNyx wires together `nmap`, `ffuf`, `gobuster`/`feroxbuster`, `arjun`, `sqlmap`, `dalfox`, `subfinder`, `cewl` and a set of built-in checks into a single, staged workflow. Point it at a target and it walks from port discovery through content enumeration to vulnerability testing, then writes a consolidated report. Run the whole flow, a single stage, or one phase at a time.

> ⚠️ **Authorized testing only.** HuntNyx is built for lab environments, CTFs (e.g. TryHackMe), and targets you have explicit written permission to test. You are responsible for how you use it.

## Features

- **Three-stage pipeline** — Discovery → Enumeration → Testing, followed by reporting.
- **Tool orchestration** — automatically detects installed tools and skips or prompts for anything missing.
- **Interactive wizard** — run with no target for a guided setup, or drive everything from flags for automation.
- **Custom wordlists** — optionally spider the target with `cewl` and reuse the result for content and vhost fuzzing.
- **Authenticated scans** — supply cookies, custom headers, or auto-login credentials.
- **Flexible input** — a bare target, extra URLs, a URL list file, or a raw Burp-style HTTP request.
- **Consolidated report** — every phase's findings collected into a single `.txt` file.

## Stages & phases

| Stage | Phases | External tools |
|-------|--------|----------------|
| **Discovery** | Ports, Fingerprint, Technologies | `nmap`, `curl` |
| **Enumeration** | Subdomains, VHosts, Crawl, Arjun (hidden params), Directories, Sensitive Files / VCS | `subfinder`, `ffuf`, `arjun`, `gobuster` / `feroxbuster` |
| **Testing** | XSS, Open Redirect, Path Traversal / LFI, SSTI, Command Injection, XXE, Security Headers, CORS, 401/403 Bypass, NoSQL Injection, SQLMap (opt-in) | `dalfox`, `sqlmap` |
| **Reporting** | Consolidated `.txt` report | — |

## Requirements

- **Python 3.8+**
- **Required tools:** `nmap`, `curl`, and a content-discovery engine (`gobuster` or `feroxbuster`), plus `ffuf` for vhost fuzzing.
- **Optional tools:** `arjun`, `sqlmap`, `dalfox`, `subfinder`, `cewl` — related phases are skipped if these are absent.

Install the common ones on a Debian/Kali-based system:

```bash
sudo apt install -y nmap gobuster ffuf seclists
pipx install arjun
go install github.com/hahwul/dalfox/v2@latest
```

Check what HuntNyx can see on your `PATH`:

```bash
huntnyx --check-deps
```

## Installation

HuntNyx is a pure-standard-library Python package (no third-party pip dependencies). Install it from a clone:

```bash
git clone https://github.com/Zent01/huntnyx.git
cd huntnyx
pip install .
```

For development, use an editable install so code changes take effect immediately:

```bash
pip install -e .
```

Either way you get a `huntnyx` command on your `PATH`. You can also run it without installing, straight from the repo root, with `python3 -m huntnyx`.

## Usage

```
huntnyx [target] [flags] [options]
```

Running with **no target** launches the interactive wizard.

### Stage & phase selection

| Flag | Description |
|------|-------------|
| `--all` | Run the full flow (default when no flags are given) |
| `--discovery` | Run the whole Discovery stage |
| `--enumeration` | Run the whole Enumeration stage |
| `--testing` | Run the whole Testing stage |
| `--<phase>` | Run a single phase, e.g. `--ports`, `--content`, `--xss` |
| `--sqlmap` | Opt in to automatic SQLMap runs on discovered params/forms |

### Common options

| Option | Description |
|--------|-------------|
| `-o, --output FILE` | Report file (default `<target>_enum.txt`) |
| `-c, --config FILE` | JSON config file (default `config.json`) |
| `--ports-list P` | Skip nmap; seed web ports, e.g. `80,443,8080` |
| `--domain D` | Domain for vhost fuzzing (else derived from target) |
| `--cookie C` | Session cookie, e.g. `'PHPSESSID=...'` |
| `--header H` | Extra header `'Name: value'` (repeatable) |
| `--login-data D` | Credentials for auto-login (authenticated scan) |
| `--login-url U` | Explicit login page for auto-login |
| `--threads N` | Concurrency for fuzzers |
| `-r, --request FILE` | Read a raw HTTP request (Burp-style) and test it |
| `--url URL` | Extra URL with params to test (repeatable) |
| `--urls FILE` | File of URLs to test (one per line) |
| `--add-hosts` | Write found vhosts to `/etc/hosts` and scan them (needs root) |
| `-y, --yes` | Non-interactive: use config wordlists, no prompts |
| `--no-color` | Disable ANSI colors |
| `--check-deps` | List tool availability and exit |
| `-v, --verbose` / `-q, --quiet` | Adjust output verbosity |
| `-h, --help` | Show colorized help and exit |

## Examples

```bash
# Full pipeline against a target
huntnyx http://site.thm --all

# Just the Testing stage, authenticated with a session cookie
huntnyx http://site.thm/?id=1 --testing --cookie 'session=...'

# Enumeration, writing discovered vhosts to /etc/hosts (root required)
sudo huntnyx http://site.thm --enumeration --add-hosts

# Discovery only, skipping nmap by seeding ports
huntnyx 10.10.10.5 --ports-list 80,8080 --discovery

# Check which tools are installed
huntnyx --check-deps
```

## Configuration

Runtime behaviour is controlled by a JSON config (default `config.json`), which is deep-merged over sensible defaults. It covers thread counts, default web ports, wordlists, extensions, per-tool timeouts, and per-phase settings (nmap, content, vhost, crawl, arjun, sqlmap, subfinder, and more). Any value you omit falls back to the built-in default.

## Reports

Each run produces a single `.txt` report grouping findings by stage and phase, including a header with the target, timestamp, phases run, and discovered web services. Override the path with `-o/--output`.

## Disclaimer

This project is intended for education, CTF practice, and authorized security assessments only. Do not use it against systems you do not own or lack explicit permission to test. The authors accept no liability for misuse.
