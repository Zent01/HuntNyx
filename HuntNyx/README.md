# HuntNyx

## Run

&#x20;   python3 HuntNyx.py <target> \[flags]
    python3 HuntNyx.py --help
    python3 HuntNyx.py http://site.thm --all


## Layout

&#x20;   HuntNyx.py            entry point
    huntnyx/
      cli.py              CLI + orchestration
      core/               shared engine (ui, config, http, validation, registry, report)
      discovery/          ports, fingerprint, technologies
      enumeration/        subdomains, vhost, crawl, arjun, content, vcs
      testing/            xss, redirect, traversal, ssti, sqlmap


External tools (optional, auto-skip if missing): nmap, gobuster/feroxbuster,
ffuf, arjun, dalfox, sqlmap, subfinder, curl.

