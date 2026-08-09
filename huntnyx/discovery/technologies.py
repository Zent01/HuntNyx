from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


_TECH_COOKIES = {"phpsessid": "PHP", "jsessionid": "Java/JSP", "laravel_session": "Laravel",
                 "csrftoken": "Django", "connect.sid": "Node/Express", "ci_session": "CodeIgniter",
                 "_session_id": "Rails", "asp.net_sessionid": "ASP.NET"}


_TECH_HTML = {"wp-content": "WordPress", "wp-includes": "WordPress", "/sites/default/files": "Drupal",
              "com_content": "Joomla", "data-reactroot": "React", "__next": "Next.js",
              "ng-version": "Angular", "vue.js": "Vue.js", "jquery": "jQuery", "bootstrap": "Bootstrap",
              "csrfmiddlewaretoken": "Django", "werkzeug": "Werkzeug/Flask", "laravel": "Laravel"}


def phase_technologies(target, config, runner):
    result = {"services": [], "errors": []}
    target.ensure_web_services(config, runner)
    if not target.web_services:
        result["errors"].append("no web services")
        return result
    for svc in target.web_services:
        tag = svc.key().replace(":", "_")
        status, headers, body, _ = _curl_full(svc.url, config, runner, f"tech_{tag}")
        if not status and not headers and not (body or ""):
            UI.warn(f"technologies {svc.url}: no response (curl failed / target unreachable)")
            result["errors"].append(f"no response from {svc.url}")
            continue
        techs = set()
        for h in ("server", "x-powered-by", "x-generator", "x-aspnet-version", "x-drupal-cache"):
            if headers.get(h):
                techs.add(f"{headers[h]}")
        sc = headers.get("set-cookie", "").lower()
        for ck, name in _TECH_COOKIES.items():
            if ck in sc:
                techs.add(name)
        blow = (body or "").lower()
        for sig, name in _TECH_HTML.items():
            if sig in blow:
                techs.add(name)
        mg = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body or "", re.I)
        if mg:
            techs.add(mg.group(1).strip())
        techs = sorted(techs)
        UI.info(f"technologies {UI.c(svc.url, UI.WHITE)}")
        if techs:
            UI.ok(", ".join(techs))
        else:
            UI.dim("      none identified")
        result["services"].append({"url": svc.url, "tech": techs})
    return result


def _r_technologies(d):
    lines = _sec("TECHNOLOGIES")
    any_t = False
    for s in d.get("services", []):
        if s.get("tech"):
            any_t = True
            lines.append(f"  {s['url']}: {', '.join(s['tech'])}")
    if not any_t:
        lines.append("  none identified")
    return lines + [""]
