#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
charguard.py — deterministic character-level / encoding pre-pass for an
outbound (egress) data path.

ROLE
    This is the *deterministic* half of the split-layer anomaly design. It runs
    BEFORE the advisory LLM inspector, in the free-text path, and catches the
    things an LLM cannot reliably catch:
      * invisible / format / control characters (Unicode category Cf/Cc/Co/Cn),
      * bidirectional-override smuggling (the "Trojan Source" class, CVE-2021-42574),
      * zero-width steganographic channels (bits encoded as invisible characters),
      * homoglyph / mixed-script confusables (UTS #39),
      * non-canonical Unicode and invalid UTF-8,
      * visible encoded blobs: base64 / hex / PEM / PGP / data-URI / high-entropy,
        including magic-byte detection on the decoded payload (embedded files).
    It emits (a) a structured JSON report for the high-side orchestrator/human,
    and (b) a SANITIZED copy of the text (canonicalised, invisibles removed) to
    hand to the downstream LLM stage so the model sees clean input.

    Why this is deterministic and not an LLM: NFC/NFKC normalisation does NOT
    remove zero-width characters, tokenizers preserve them while classifiers fail
    to alarm on them, and entropy/charset structure is a statistical property an
    LLM does not measure by inspection. A byte/codepoint pass is near-perfect and
    near-free for exactly this job.

DESIGN CONSTRAINTS
    * Ubuntu-supported and air-gap-safe: standard library ONLY. No pip, no wheels,
      no network, no external data files required. Runs on the python3 that ships
      with Ubuntu (tested against 3.8+). Nothing to download or vet beyond the
      interpreter.
    * Deterministic and auditable: no randomness, no models, single file.
    * Multilingual-safe (Singapore context: English/Chinese/Malay/Tamil): the
      detectors are tuned so that legitimately multilingual or RTL text does NOT
      false-positive. Intra-token Latin+Cyrillic/Greek mixing is the high-confidence
      confusable signal; document-level script mixing (e.g. English + Chinese) is
      treated as normal. Zero-width joiners used sparsely (emoji, Indic/Persian
      shaping) are stripped and noted but not blocked; only dense/structured runs
      are treated as a covert channel.

OUTPUT / EXIT CODES (for pipeline integration)
    0 = PASS      (no findings)
    2 = REVIEW    (findings present, highest severity MEDIUM/LOW -> human triage)
    3 = BLOCK     (highest severity HIGH -> reject)
    4 = ERROR / UNASSESSABLE (invalid UTF-8 etc.; treat as BLOCK, fail-closed)

USAGE
    charguard.py INPUT.txt                      # report JSON to stdout
    cat INPUT.txt | charguard.py                # read from stdin
    charguard.py INPUT.txt --sanitized-out clean.txt
    charguard.py --selftest                     # run built-in attack-payload tests

NOTE ON THE REPORT AS A CHANNEL
    The JSON report is detailed (codepoints, positions) because it is consumed on
    the HIGH side by the orchestrator/reviewer and never crosses the boundary. If
    you ever forward this report to a lower enclave, treat its fields as channel
    capacity and reduce them (drop positions/codepoints) exactly as you would the
    LLM verdict.
"""

import sys
import re
import json
import math
import base64
import argparse
import unicodedata
from collections import Counter

VERSION = "1.0"

# ----------------------------------------------------------------------------
# Tunable thresholds (kept explicit at the top for accreditation review).
# ----------------------------------------------------------------------------
CFG = {
    # Allowed whitespace that is NOT treated as a control/invisible anomaly.
    "allowed_ws": {"\t", "\n", "\r", "\x20"},
    # Zero-width "channel" heuristics.
    "zw_run_threshold": 8,        # contiguous run of zero-width chars => covert channel
    "zw_total_threshold": 20,     # total zero-width chars in doc => covert channel
    "zw_ratio_threshold": 0.02,   # zero-width : visible ratio => covert channel
    "zw_ratio_min_count": 8,      # ratio test only applies once this many ZW chars seen
                                  # (so a lone emoji joiner is not mistaken for a channel)
    # Encoded-blob minimums (avoid flagging short hashes/ids/tokens).
    "base64_min_len": 40,         # contiguous base64-alphabet chars
    "hex_min_len": 40,            # contiguous hex chars (>= 20 bytes)
    # High-entropy sliding window.
    "entropy_window": 256,
    "entropy_step": 128,
    "entropy_bits_threshold": 5.0,   # bits/char; natural language ~4.0-4.7
    "entropy_alpha_ratio": 0.85,     # window must be mostly alnum to qualify
    # Decoded-blob escalation.
    "decoded_entropy_ratio": 0.90,   # escalate if entropy >= ratio * log2(min(256,len))
    "decoded_min_maxent": 5.0,       # ...and the theoretical max entropy is at least this
    "magic_min_decoded": 8,          # min decoded bytes before trusting a signature
    # Reporting caps (bound the report so it can't itself become large).
    "max_positions": 50,
}

# ----------------------------------------------------------------------------
# Codepoint sets that need explicit handling beyond Unicode general category.
# ----------------------------------------------------------------------------

# Bidirectional FORMATTING that reorders visible text -> the Trojan Source class.
# (Overrides, embeddings, isolates and their terminators.) These essentially
# never belong in sanitised outbound text and are treated as HIGH.
BIDI_DANGEROUS = {
    "\u202A",  # LRE  LEFT-TO-RIGHT EMBEDDING
    "\u202B",  # RLE  RIGHT-TO-LEFT EMBEDDING
    "\u202C",  # PDF  POP DIRECTIONAL FORMATTING
    "\u202D",  # LRO  LEFT-TO-RIGHT OVERRIDE
    "\u202E",  # RLO  RIGHT-TO-LEFT OVERRIDE
    "\u2066",  # LRI  LEFT-TO-RIGHT ISOLATE
    "\u2067",  # RLI  RIGHT-TO-LEFT ISOLATE
    "\u2068",  # FSI  FIRST STRONG ISOLATE
    "\u2069",  # PDI  POP DIRECTIONAL ISOLATE
}

# Bidi MARKS (legitimately used in Arabic/Hebrew). Stripped & noted, not blocked.
BIDI_MARKS = {"\u200E", "\u200F", "\u061C"}  # LRM, RLM, ALM

# Zero-width characters usable as a steganographic / fragmentation channel.
ZERO_WIDTH = {
    "\u200B",  # ZERO WIDTH SPACE
    "\u200C",  # ZERO WIDTH NON-JOINER
    "\u200D",  # ZERO WIDTH JOINER
    "\u2060",  # WORD JOINER
    "\u2061",  # FUNCTION APPLICATION
    "\u2062",  # INVISIBLE TIMES
    "\u2063",  # INVISIBLE SEPARATOR
    "\u2064",  # INVISIBLE PLUS
    "\uFEFF",  # ZERO WIDTH NO-BREAK SPACE / BOM
    "\u180E",  # MONGOLIAN VOWEL SEPARATOR
}

# Unicode "Tags" block — pure steganography / instruction-smuggling vehicle.
def _is_tag_char(cp):
    return 0xE0000 <= cp <= 0xE007F

# Variation selectors (legit in emoji; only suspicious when dense). Noted low.
def _is_variation_selector(cp):
    return (0xFE00 <= cp <= 0xFE0F) or (0xE0100 <= cp <= 0xE01EF)

# Magic byte signatures for embedded-file detection on DECODED blobs.
MAGIC_SIGNATURES = [
    (b"PK\x03\x04", "ZIP/OOXML(docx,xlsx,pptx,jar)"),
    (b"PK\x05\x06", "ZIP(empty)"),
    (b"PK\x07\x08", "ZIP(spanned)"),
    (b"%PDF", "PDF"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"\x1f\x8b", "GZIP"),
    (b"BZh", "BZIP2"),
    (b"7z\xbc\xaf\x27\x1c", "7-ZIP"),
    (b"Rar!\x1a\x07\x00", "RAR(v4)"),
    (b"Rar!\x1a\x07\x01\x00", "RAR(v5)"),
    (b"\xfd7zXZ\x00", "XZ"),
    (b"\x04\x22\x4d\x18", "LZ4"),
    (b"\x28\xb5\x2f\xfd", "ZSTD"),
    (b"\x7fELF", "ELF-executable"),
    (b"MZ", "DOS/PE-executable"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "MS-OLE(legacy office)"),
    (b"OggS", "OGG"),
    (b"\x1aE\xdf\xa3", "Matroska/WebM"),
    (b"SQLite format 3\x00", "SQLite-db"),
]

# Regexes for visible encoded structure.
RE_BASE64 = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % CFG["base64_min_len"])
RE_BASE64URL = re.compile(r"[A-Za-z0-9_\-]{%d,}={0,2}" % CFG["base64_min_len"])
RE_HEX = re.compile(r"(?:[0-9A-Fa-f]{2}[\s:.\-]?){%d,}" % (CFG["hex_min_len"] // 2))
RE_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]+-----")
RE_DATA_URI = re.compile(r"data:[^;,\s]*;base64,([A-Za-z0-9+/=]+)")
RE_LETTERS = re.compile(r"[^\W\d_]+", re.UNICODE)  # runs of Unicode letters


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def shannon_entropy(seq):
    """Shannon entropy in bits per symbol over a string or bytes."""
    if not seq:
        return 0.0
    n = len(seq)
    counts = Counter(seq)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def char_script(ch):
    """Coarse script bucket via the Unicode character NAME prefix (stdlib only).

    Returns 'Latin' / 'Cyrillic' / 'Greek' / 'Common' / 'Other'. 'Common' covers
    shared characters (punctuation, digits, symbols, whitespace) so they never
    trigger a mixed-script finding.
    """
    cat = unicodedata.category(ch)
    if cat[0] in ("P", "S", "Z", "N", "C") or ch.isspace():
        return "Common"
    name = unicodedata.name(ch, "")
    if name.startswith("LATIN"):
        return "Latin"
    if name.startswith("CYRILLIC"):
        return "Cyrillic"
    if name.startswith("GREEK") or name.startswith("COPTIC"):
        return "Greek"
    return "Other"


def _cps(s):
    """List of (index, char) for reporting, capped."""
    out = []
    for i, ch in enumerate(s):
        out.append((i, ch))
        if len(out) >= CFG["max_positions"]:
            break
    return out


def _u(ch):
    return "U+%04X" % ord(ch)


# ----------------------------------------------------------------------------
# Detectors. Each appends 0+ findings; each finding is a dict.
# ----------------------------------------------------------------------------
def detect_invisibles(text, findings):
    """Format/control/private-use/unassigned/bidi/zero-width characters."""
    invis_positions = []      # generic invisibles (Cf/Cc/Co/Cn, non-ws)
    bidi_positions = []       # dangerous bidi overrides/isolates
    bidi_mark_positions = []  # LRM/RLM/ALM
    zw_positions = []         # zero-width channel candidates
    tag_positions = []        # Unicode Tags block
    vs_positions = []         # variation selectors

    for i, ch in enumerate(text):
        cp = ord(ch)
        if ch in CFG["allowed_ws"]:
            continue
        if ch in BIDI_DANGEROUS:
            bidi_positions.append(i)
            continue
        if ch in BIDI_MARKS:
            bidi_mark_positions.append(i)
            continue
        if _is_tag_char(cp):
            tag_positions.append(i)
            continue
        if ch in ZERO_WIDTH:
            zw_positions.append(i)
            continue
        if _is_variation_selector(cp):
            vs_positions.append(i)
            continue
        cat = unicodedata.category(ch)
        # Cf=format, Cc=other control, Co=private use, Cn=unassigned.
        if cat in ("Cf", "Cc", "Co", "Cn"):
            invis_positions.append(i)

    # --- Bidi overrides/isolates: Trojan Source class -> HIGH ---
    if bidi_positions:
        findings.append({
            "code": "BIDI_CONTROL",
            "severity": "HIGH",
            "count": _bucket(len(bidi_positions)),
            "detail": "bidirectional override/isolate formatting (Trojan Source / CVE-2021-42574)",
            "positions": bidi_positions[:CFG["max_positions"]],
        })

    # --- Unicode Tags block: pure smuggling vehicle -> HIGH ---
    if tag_positions:
        findings.append({
            "code": "TAG_CHARS",
            "severity": "HIGH",
            "count": _bucket(len(tag_positions)),
            "detail": "Unicode Tags block (U+E0000..U+E007F) — steganographic/instruction smuggling",
            "positions": tag_positions[:CFG["max_positions"]],
        })

    # --- Zero-width: distinguish covert channel from sparse legit use ---
    if zw_positions:
        runs = _max_run(zw_positions)
        visible = max(1, len(text) - len(zw_positions))
        ratio = len(zw_positions) / visible
        is_channel = (
            runs >= CFG["zw_run_threshold"]
            or len(zw_positions) >= CFG["zw_total_threshold"]
            or (len(zw_positions) >= CFG["zw_ratio_min_count"] and ratio >= CFG["zw_ratio_threshold"])
        )
        if is_channel:
            findings.append({
                "code": "ZEROWIDTH_CHANNEL",
                "severity": "HIGH",
                "count": _bucket(len(zw_positions)),
                "detail": "dense/structured zero-width run — likely steganographic binary channel "
                          "(max_run=%d, ratio=%.4f)" % (runs, ratio),
                "positions": zw_positions[:CFG["max_positions"]],
            })
        else:
            findings.append({
                "code": "ZEROWIDTH_SPARSE",
                "severity": "LOW",
                "count": _bucket(len(zw_positions)),
                "detail": "sparse zero-width characters (stripped; commonly benign emoji/Indic shaping)",
                "positions": zw_positions[:CFG["max_positions"]],
            })

    # --- Other invisibles (format/control/private/unassigned) ---
    if invis_positions:
        sev = "MEDIUM" if len(invis_positions) >= CFG["zw_total_threshold"] else "LOW"
        findings.append({
            "code": "INVISIBLE_CHARS",
            "severity": sev,
            "count": _bucket(len(invis_positions)),
            "detail": "format/control/private-use/unassigned characters (Cf/Cc/Co/Cn)",
            "positions": invis_positions[:CFG["max_positions"]],
        })

    # --- Bidi marks (lower severity; legit in RTL) ---
    if bidi_mark_positions:
        findings.append({
            "code": "BIDI_MARK",
            "severity": "LOW",
            "count": _bucket(len(bidi_mark_positions)),
            "detail": "directional marks LRM/RLM/ALM (stripped; legitimate in RTL text)",
            "positions": bidi_mark_positions[:CFG["max_positions"]],
        })

    # --- Variation selectors only flagged when dense ---
    if len(vs_positions) >= CFG["zw_run_threshold"]:
        findings.append({
            "code": "VARIATION_SELECTORS",
            "severity": "MEDIUM",
            "count": _bucket(len(vs_positions)),
            "detail": "dense variation selectors — possible covert channel",
            "positions": vs_positions[:CFG["max_positions"]],
        })


def detect_mixed_script(text, findings):
    """Intra-token Latin+Cyrillic/Greek mixing = high-confidence homoglyph spoof.

    Document-level mixing (English + Chinese, etc.) is intentionally NOT flagged.
    """
    flagged = []
    other_mixed = []
    for m in RE_LETTERS.finditer(text):
        tok = m.group(0)
        scripts = set()
        for ch in tok:
            s = char_script(ch)
            if s != "Common":
                scripts.add(s)
        scripts.discard("Common")
        if "Latin" in scripts and ("Cyrillic" in scripts or "Greek" in scripts):
            flagged.append((m.start(), tok))
        elif len(scripts) > 1:
            other_mixed.append((m.start(), tok))

    if flagged:
        findings.append({
            "code": "HOMOGLYPH_MIXED_SCRIPT",
            "severity": "HIGH",
            "count": _bucket(len(flagged)),
            "detail": "token mixes Latin with Cyrillic/Greek look-alikes (UTS #39 confusable spoof)",
            "samples": [t for _, t in flagged[:10]],
            "positions": [p for p, _ in flagged[:CFG["max_positions"]]],
        })
    if other_mixed:
        findings.append({
            "code": "MIXED_SCRIPT_OTHER",
            "severity": "LOW",
            "count": _bucket(len(other_mixed)),
            "detail": "token mixes scripts (lower confidence; can be legitimate, e.g. product names)",
            "samples": [t for _, t in other_mixed[:10]],
        })


def detect_canonical(raw_text, findings):
    """Flag text that is not in NFC (non-canonical sequences can mask content)."""
    if raw_text != unicodedata.normalize("NFC", raw_text):
        findings.append({
            "code": "NON_NFC",
            "severity": "LOW",
            "count": "1",
            "detail": "text is not in NFC canonical form (normalised in sanitised output)",
        })


def _scan_blob(decoded, source_code, findings, where):
    """Inspect a decoded byte blob: magic signature and entropy. Internal only —
    decoded bytes are NEVER emitted, only a verdict about them."""
    escalate = False
    if len(decoded) >= CFG["magic_min_decoded"]:
        for sig, label in MAGIC_SIGNATURES:
            if decoded.startswith(sig):
                findings.append({
                    "code": "EMBEDDED_FILE_SIGNATURE",
                    "severity": "HIGH",
                    "count": "1",
                    "detail": "%s blob at %s decodes to an embedded %s file" % (source_code, where, label),
                })
                escalate = True
                break
    if not escalate and len(decoded) >= 32:
        ent = shannon_entropy(decoded)
        max_ent = math.log2(min(256, len(decoded)))
        if max_ent >= CFG["decoded_min_maxent"] and ent >= CFG["decoded_entropy_ratio"] * max_ent:
            findings.append({
                "code": "ENCRYPTED_OR_COMPRESSED",
                "severity": "HIGH",
                "count": "1",
                "detail": "%s blob at %s decodes to near-maximal-entropy bytes (%.2f of %.2f bits/byte) — "
                          "likely encrypted/compressed payload" % (source_code, where, ent, max_ent),
            })
            escalate = True
    return escalate


def detect_encoded(text, findings):
    """Visible encoded structure: PEM/PGP, data-URI, base64, hex, high-entropy."""
    # PEM / PGP armoured blocks.
    pem = list(RE_PEM.finditer(text))
    if pem:
        labels = sorted({m.group(0) for m in pem})
        findings.append({
            "code": "PEM_PGP_BLOCK",
            "severity": "HIGH",
            "count": _bucket(len(pem)),
            "detail": "armoured key/cert/PGP block(s): " + "; ".join(labels[:5]),
            "positions": [m.start() for m in pem][:CFG["max_positions"]],
        })

    # data: URIs with base64 payloads.
    for m in RE_DATA_URI.finditer(text):
        payload = m.group(1)
        findings.append({
            "code": "DATA_URI",
            "severity": "MEDIUM",
            "count": "1",
            "detail": "base64 data: URI embedded in text",
            "positions": [m.start()],
        })
        try:
            dec = base64.b64decode(payload + "=" * (-len(payload) % 4), validate=False)
            _scan_blob(dec, "data-URI", findings, "offset %d" % m.start())
        except Exception:
            pass

    # Standard base64 blobs (and url-safe variant). Pure-hex runs are deferred
    # to the hex detector below (hex is a subset of the base64 alphabet).
    b64_spans = []
    for rx, tag in ((RE_BASE64, "base64"), (RE_BASE64URL, "base64url")):
        for m in rx.finditer(text):
            span = (m.start(), m.end())
            blob = m.group(0)
            if re.fullmatch(r"[0-9A-Fa-f]+", blob) and len(blob) % 2 == 0:
                continue  # pure hex -> handled by the hex detector
            if any(span[0] >= s and span[1] <= e for s, e in b64_spans):
                continue
            b64_spans.append(span)
            escalated = False
            try:
                norm = blob.replace("-", "+").replace("_", "/")
                dec = base64.b64decode(norm + "=" * (-len(norm) % 4), validate=False)
                escalated = _scan_blob(dec, tag, findings, "offset %d" % m.start())
            except Exception:
                pass
            if not escalated:
                findings.append({
                    "code": "BASE64_BLOB",
                    "severity": "MEDIUM",
                    "count": "1",
                    "detail": "long %s run (%d chars) embedded in free text" % (tag, len(blob)),
                    "positions": [m.start()],
                })

    # Long hex strings (skip runs already covered by a base64 blob span).
    for m in RE_HEX.finditer(text):
        if any(m.start() >= s and m.end() <= e for s, e in b64_spans):
            continue
        raw = re.sub(r"[\s:.\-]", "", m.group(0))
        if len(raw) < CFG["hex_min_len"]:
            continue
        escalated = False
        try:
            dec = bytes.fromhex(raw[: len(raw) - (len(raw) % 2)])
            escalated = _scan_blob(dec, "hex", findings, "offset %d" % m.start())
        except Exception:
            pass
        if not escalated:
            findings.append({
                "code": "HEX_BLOB",
                "severity": "MEDIUM",
                "count": "1",
                "detail": "long hex run (%d chars) embedded in free text" % len(raw),
                "positions": [m.start()],
            })

    # Sliding-window high entropy (catches encoded blobs missed by the regexes).
    w, step = CFG["entropy_window"], CFG["entropy_step"]
    if len(text) >= w:
        hot = []
        for i in range(0, len(text) - w + 1, step):
            window = text[i:i + w]
            alpha = sum(c.isalnum() for c in window) / w
            if alpha < CFG["entropy_alpha_ratio"]:
                continue
            if shannon_entropy(window) >= CFG["entropy_bits_threshold"]:
                hot.append(i)
        if hot:
            findings.append({
                "code": "HIGH_ENTROPY_REGION",
                "severity": "MEDIUM",
                "count": _bucket(len(hot)),
                "detail": "alnum-dense region(s) with entropy >= %.1f bits/char — possible encoded payload"
                          % CFG["entropy_bits_threshold"],
                "positions": hot[:CFG["max_positions"]],
            })


# ----------------------------------------------------------------------------
# Sanitiser: produce the clean text for the downstream LLM stage.
# ----------------------------------------------------------------------------
def sanitise(text):
    """Remove invisibles/format/control (except allowed ws) and NFC-normalise.
    Homoglyphs are NOT folded by default (folding could corrupt legitimate
    non-Latin text); they are reported instead."""
    out = []
    for ch in text:
        cp = ord(ch)
        if ch in CFG["allowed_ws"]:
            out.append(ch)
            continue
        if ch in BIDI_DANGEROUS or ch in BIDI_MARKS or ch in ZERO_WIDTH:
            continue
        if _is_tag_char(cp) or _is_variation_selector(cp):
            continue
        if unicodedata.category(ch) in ("Cf", "Cc", "Co", "Cn"):
            continue
        out.append(ch)
    return unicodedata.normalize("NFC", "".join(out))


# ----------------------------------------------------------------------------
# Small utilities for bounded reporting.
# ----------------------------------------------------------------------------
def _bucket(n):
    if n <= 0:
        return "0"
    if n == 1:
        return "1"
    if n == 2:
        return "2"
    return "3+"


def _max_run(sorted_positions):
    """Longest run of consecutive indices in a sorted position list."""
    best = cur = 0
    prev = None
    for p in sorted_positions:
        if prev is not None and p == prev + 1:
            cur += 1
        else:
            cur = 1
        best = max(best, cur)
        prev = p
    return best


SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def decide(findings, assessable):
    if not assessable:
        return "BLOCK", "HIGH"
    if not findings:
        return "PASS", "NONE"
    top = max(SEV_RANK[f["severity"]] for f in findings)
    if top == 3:
        return "BLOCK", "HIGH"
    if top == 2:
        return "REVIEW", "MEDIUM"
    return "PASS", "LOW"


# ----------------------------------------------------------------------------
# Top-level analysis.
# ----------------------------------------------------------------------------
def analyze(data):
    """data: raw bytes. Returns (report_dict, sanitized_text_or_None)."""
    report = {
        "tool": "charguard",
        "version": VERSION,
        "unicode_version": unicodedata.unidata_version,
        "input_bytes": len(data),
        "assessable": True,
        "findings": [],
    }

    # Detect and strip a leading UTF-8 BOM, then validate UTF-8 strictly.
    had_bom = data.startswith(b"\xef\xbb\xbf")
    if had_bom:
        data = data[3:]
        report["findings"].append({
            "code": "INVISIBLE_CHARS", "severity": "LOW", "count": "1",
            "detail": "leading UTF-8 BOM (stripped)",
        })

    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as e:
        report["assessable"] = False
        report["findings"].append({
            "code": "INVALID_UTF8", "severity": "HIGH", "count": "1",
            "detail": "input is not valid UTF-8 (%s at byte %d) — possible encoding smuggling" % (e.reason, e.start),
        })
        report["decision"], report["risk_tier"] = decide(report["findings"], False)
        return report, None

    findings = report["findings"]
    detect_invisibles(text, findings)
    detect_mixed_script(text, findings)
    detect_canonical(text, findings)
    detect_encoded(text, findings)

    report["decision"], report["risk_tier"] = decide(findings, report["assessable"])
    sanitized = sanitise(text)
    return report, sanitized


EXIT = {"PASS": 0, "REVIEW": 2, "BLOCK": 3}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Deterministic character-level / encoding pre-pass.")
    ap.add_argument("input", nargs="?", help="input file (default: stdin)")
    ap.add_argument("--sanitized-out", help="write the sanitised text to this path")
    ap.add_argument("--compact", action="store_true", help="compact JSON")
    ap.add_argument("--selftest", action="store_true", help="run built-in attack-payload tests")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if args.input:
        with open(args.input, "rb") as fh:
            data = fh.read()
    else:
        data = sys.stdin.buffer.read()

    report, sanitized = analyze(data)

    if args.sanitized_out and sanitized is not None:
        with open(args.sanitized_out, "w", encoding="utf-8") as fh:
            fh.write(sanitized)
        report["sanitized_out"] = args.sanitized_out

    print(json.dumps(report, indent=None if args.compact else 2, ensure_ascii=False))
    return EXIT.get(report["decision"], 4)


# ----------------------------------------------------------------------------
# Built-in self-test: constructs known payloads offline and asserts detection.
# ----------------------------------------------------------------------------
def selftest():
    failures = []

    def check(name, data, expect_decision, expect_codes):
        rep, _ = analyze(data if isinstance(data, bytes) else data.encode("utf-8"))
        codes = {f["code"] for f in rep["findings"]}
        ok = rep["decision"] == expect_decision and set(expect_codes).issubset(codes)
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures.append((name, rep["decision"], sorted(codes)))
        print("[%s] %-34s -> decision=%-6s codes=%s" % (status, name, rep["decision"], sorted(codes)))

    # 1. Clean English — must PASS.
    check("clean_english", "Employee onboarding checklist for the Q3 intake cohort.",
          "PASS", [])

    # 2. Legitimate multilingual (must NOT false-positive).
    check("clean_multilingual", "Name: 陈伟明 / Encik Ahmad bin Hassan / பெயர்: ராஜ்.",
          "PASS", [])

    # 3. Bidi Trojan Source override.
    check("bidi_trojan_source", "salary = 1000\u202E000 # reversed",
          "BLOCK", ["BIDI_CONTROL"])

    # 4. Zero-width binary channel (10 chars x 8 bits of ZW).
    payload = "Looks totally normal." + ("\u200B\u200C" * 40)
    check("zerowidth_channel", payload, "BLOCK", ["ZEROWIDTH_CHANNEL"])

    # 5. Homoglyph: 'password' with Cyrillic 'а' and 'о'.
    check("homoglyph_cyrillic", "Please reset your p\u0430ssw\u043Erd today.",
          "BLOCK", ["HOMOGLYPH_MIXED_SCRIPT"])

    # 6. Unicode Tags smuggling.
    tags = "".join(chr(0xE0000 + i) for i in (65, 66, 67))
    check("unicode_tags", "Hello" + tags + "world", "BLOCK", ["TAG_CHARS"])

    # 7. Base64 that decodes to a ZIP/OOXML file (embedded attachment).
    zip_b64 = base64.b64encode(b"PK\x03\x04" + b"\x00" * 60).decode()
    check("embedded_zip_base64", "see attachment: " + zip_b64,
          "BLOCK", ["EMBEDDED_FILE_SIGNATURE"])

    # 8. Base64 of high-entropy (encrypted) bytes.
    import os
    enc_b64 = base64.b64encode(os.urandom(128)).decode()
    check("encrypted_blob_base64", "ref " + enc_b64, "BLOCK", ["ENCRYPTED_OR_COMPRESSED"])

    # 9. PEM private key block.
    check("pem_private_key",
          "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA....\n-----END OPENSSH PRIVATE KEY-----",
          "BLOCK", ["PEM_PGP_BLOCK"])

    # 10. Long hex string decoding to random bytes.
    hexblob = os.urandom(64).hex()
    check("hex_blob", "token=" + hexblob, "BLOCK", ["ENCRYPTED_OR_COMPRESSED"])

    # 11. Sparse zero-width (single ZWJ in emoji) — stripped, noted, not gated.
    check("benign_zwj_emoji", "Great work team \U0001F468\u200D\U0001F4BB shipping today!",
          "PASS", ["ZEROWIDTH_SPARSE"])

    # 12. Invalid UTF-8 — fail-closed.
    check("invalid_utf8", b"normal text \xff\xfe broken", "BLOCK", ["INVALID_UTF8"])

    print("-" * 60)
    if failures:
        print("SELFTEST FAILURES: %d" % len(failures))
        for name, dec, codes in failures:
            print("   %s: decision=%s codes=%s" % (name, dec, codes))
        return 1
    print("ALL SELFTESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
