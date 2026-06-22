"""Deterministic, high-side evidence locators.

When the *inspector* flags a category on a segment, these locators find the
concrete span(s) of overt content behind it, so the reviewer console can point
at them in the original text. Highlighting is therefore tied to findings: a
locator only runs for a category the inspector already raised on that segment.

This is plain regex over text the high-side console already holds. It never runs
against, or feeds, the inspector LLM, so it adds no model-driven channel — it
only helps a human reviewer see what was flagged.

Each locator entry is ``(compiled_regex, mask, group)``:
  * ``mask`` True  -> the span is a secret/PII *value*; the console masks it and
                      offers click-to-reveal (the cleartext is never sent until
                      an explicit, audited reveal request).
  * ``group``      -> which capture group delimits the span (0 = whole match;
                      for ``key=value`` credentials we mark only the value).

A category with no locator here (e.g. PROPRIETARY_IP, SENSITIVITY_SPIKE, PHI —
all semantic) simply yields no spans: the segment text is shown, nothing is
highlighted, and the reviewer reads it themselves.
"""
import re

_I = re.IGNORECASE

# --- secrets: mark only the value, so the surrounding key gives context -------
_CRED = [
    (re.compile(r"\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|"
                r"secret[_-]?key|client[_-]?secret|token|auth[_-]?token|bearer)\b"
                r"\s*[:=]\s*(?P<val>\S+)", _I), True, "val"),
    # prose form ("password Wint3r2026!Go"): only when the value looks like a
    # credential (mixes letters and digits, >=6 chars) so "password policy" is ignored.
    (re.compile(r"\b(?:password|passwd|pwd|passphrase)\b\s+"
                r"(?P<val>(?=\S*[A-Za-z])(?=\S*\d)\S{6,})", _I), True, "val"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                re.S), True, 0),
    (re.compile(r"-----BEGIN [A-Z ]+-----"), True, 0),
]

# --- classification markings (highlight, not masked) --------------------------
_MARK = [
    (re.compile(r"\b(?:TOP SECRET|SECRET|CONFIDENTIAL|RESTRICTED|CUI|FOUO|"
                r"FOR OFFICIAL USE ONLY|OFFICIAL[- ]SENSITIVE|COSMIC TOP SECRET|"
                r"NATO (?:SECRET|CONFIDENTIAL|RESTRICTED)|RESTREINT UE|"
                r"DISTRIBUTION STATEMENT [A-F]|EXPORT CONTROLLED|ITAR)\b"
                r"(?:\s*//\s*[A-Z]+)*", _I), False, 0),
    (re.compile(r"\(\s*[A-Z]{1,4}//[A-Z/ ]+\)"), False, 0),     # portion marks: (S//NF)
    (re.compile(r"\b[A-Z]//[A-Z]{2,}\b"), False, 0),           # bare: S//NF
]
_CAVEAT = [
    (re.compile(r"\b(?:NOFORN|ORCON|PROPIN|IMCON|RELIDO|EYES ONLY|EXDIS|NODIS)\b"), False, 0),
    (re.compile(r"\bREL TO\b[ A-Z,]+"), False, 0),
]
_COMPART = [
    (re.compile(r"\bTS//SCI\b|\bSCI\b|//SI\b|//TK\b|//HCS\b|\bSAP\b|\bSI/TK\b"), False, 0),
]

# --- personal / financial identifiers (masked) -------------------------------
_PII = [
    (re.compile(r"\b[STFGM]\d{7}[A-Z]\b"), True, 0),           # NRIC / FIN
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), True, 0),           # US SSN
]
_FIN = [
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), True, 0),          # payment-card-like
    (re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{0,4}\b"), True, 0),  # IBAN-like
]

# --- internal infrastructure (highlight) -------------------------------------
_INFRA = [
    (re.compile(r"\b(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), False, 0),
    (re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"), False, 0),
    (re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"), False, 0),
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), False, 0),   # any IPv4 (catch-all)
    (re.compile(r"\b[a-z0-9][a-z0-9-]*\.(?:intranet|internal|local|corp|lan|priv)\b"
                r"(?:\.[a-z0-9-]+)*", _I), False, 0),
]
_RESIDUE = [
    (re.compile(r"\[\s*(?:REDACTED|REMOVED|DELETED|CLASSIFIED|SANITI[SZ]ED|X{2,})\s*\]", _I),
     False, 0),
]
_OPSEC = [
    (re.compile(r"\b\d{1,3}\.\d{3,}\s*[NS]?\s*,?\s*\d{1,3}\.\d{3,}\s*[EW]?\b"), False, 0),  # coords
]
_ENCODING = [
    (re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}"), False, 0),     # base64 run
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}){20,}\b"), False, 0),    # hex run
]

LOCATORS = {
    "SECRET_CREDENTIAL":   _CRED,
    "CLASS_MARKING":       _MARK,
    "DISSEM_CAVEAT":       _CAVEAT,
    "CODEWORD_COMPARTMENT": _COMPART,
    "PII":                 _PII,
    "PCI_FINANCIAL":       _FIN,
    "INFRA_IDENTIFIER":    _INFRA,
    "SANITIZATION_RESIDUE": _RESIDUE,
    "OPSEC_CONTEXT":       _OPSEC,
    "ENCODING_ANOMALY":    _ENCODING,
}


def locate(code, text):
    """Spans for one category code in text -> list of (start, end, mask, code)."""
    out = []
    for rx, mask, grp in LOCATORS.get(code, ()):
        for m in rx.finditer(text):
            try:
                s, e = m.span(grp)
            except (IndexError, re.error):
                s, e = m.span(0)
            if e > s:
                out.append((s, e, mask, code))
    return out


def merge_spans(spans):
    """Merge overlapping/adjacent spans. A merged span is masked if ANY of its
    constituents is masked; it keeps the first constituent's code (for labelling).
    Input/return tuples are (start, end, mask, code)."""
    if not spans:
        return []
    spans = sorted(spans, key=lambda x: (x[0], x[1]))
    out = [list(spans[0])]
    for s, e, mask, code in spans[1:]:
        last = out[-1]
        if s <= last[1]:                       # overlap or adjacency
            last[1] = max(last[1], e)
            last[2] = last[2] or mask
        else:
            out.append([s, e, mask, code])
    return [tuple(x) for x in out]
