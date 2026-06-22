"""Maps internal finding codes to user-facing titles and explanations.

This is what turns a quantized verdict (codes + severities) into the readable
drill-down the console shows. Deterministic stages (charguard) also supply the
verbatim captured span; the inspector supplies only the code, which we render
into plain English here.
"""

# code -> (title, explanation)
EXPLAIN = {
    # ---- charguard (deterministic character/encoding stage) ----
    "BIDI_CONTROL": ("Bidirectional text override",
        "Hidden direction-control characters were found. These reorder how text "
        "displays versus how it is stored (the 'Trojan Source' technique) and can "
        "make content read differently to a human than to a machine."),
    "TAG_CHARS": ("Hidden Unicode 'tag' characters",
        "Invisible Unicode Tags-block characters were found. They render as nothing "
        "but can smuggle hidden text or instructions."),
    "ZEROWIDTH_CHANNEL": ("Hidden data in invisible characters",
        "A dense run of zero-width (invisible) characters was found — a pattern used "
        "to encode hidden data inside otherwise normal-looking text."),
    "ZEROWIDTH_SPARSE": ("A few invisible characters",
        "A small number of zero-width characters were present and removed. Often "
        "harmless (emoji or certain scripts use them), shown for completeness."),
    "INVISIBLE_CHARS": ("Invisible / control characters",
        "Formatting or control characters that do not display were found and removed."),
    "BIDI_MARK": ("Directional marks",
        "Left/right directional marks were found and removed. Legitimate in "
        "right-to-left text; shown for completeness."),
    "VARIATION_SELECTORS": ("Unusual variation selectors",
        "An unusual concentration of variation-selector characters was found — "
        "occasionally used to hide data."),
    "HOMOGLYPH_MIXED_SCRIPT": ("Look-alike character spoofing",
        "A word mixes alphabets that look identical (e.g. a Latin 'a' swapped for a "
        "Cyrillic one). This is used to disguise words from filters."),
    "MIXED_SCRIPT_OTHER": ("Mixed-script word",
        "A word combines characters from more than one script. Sometimes legitimate "
        "(product names), shown for awareness."),
    "NON_NFC": ("Non-standard character encoding",
        "Text was not in a canonical Unicode form and was normalised."),
    "INVALID_UTF8": ("Invalid text encoding",
        "The content was not valid UTF-8 text. It could not be safely inspected, so "
        "it is blocked as a precaution."),
    "BASE64_BLOB": ("Base64-encoded block",
        "A long base64-encoded block was found embedded in the text."),
    "HEX_BLOB": ("Hex-encoded block",
        "A long hexadecimal block was found embedded in the text."),
    "DATA_URI": ("Embedded data URI",
        "A base64 'data:' URI (often an embedded image or file) was found in the text."),
    "PEM_PGP_BLOCK": ("Key / certificate / PGP block",
        "An armoured cryptographic block (key, certificate, or PGP message) was found."),
    "EMBEDDED_FILE_SIGNATURE": ("Embedded file detected",
        "An encoded block decodes to a recognisable file (e.g. a ZIP, PDF, or "
        "executable) hidden inside the text."),
    "ENCRYPTED_OR_COMPRESSED": ("Encrypted or compressed payload",
        "An encoded block decodes to high-randomness data consistent with encrypted "
        "or compressed content."),
    "HIGH_ENTROPY_REGION": ("High-randomness region",
        "A region of text has unusually high randomness, consistent with encoded or "
        "obfuscated content."),

    # ---- Prompt Guard 2 (injection stage) ----
    "INJECTION_ATTEMPT": ("Prompt-injection attempt",
        "The content contains text that tries to manipulate the inspection system "
        "itself (e.g. instructions to ignore rules). Treated as suspicious."),

    # ---- inspector (LLM judgment stage) ----
    "CLASS_MARKING": ("Classification marking",
        "A classification banner or portion marking was found (e.g. SECRET, CONFIDENTIAL, "
        "CUI, OFFICIAL-SENSITIVE, NATO/EU markings). Markings should not appear in "
        "releasable content."),
    "DISSEM_CAVEAT": ("Dissemination caveat",
        "A handling/dissemination caveat was found (e.g. NOFORN, ORCON, EYES ONLY). "
        "These indicate restricted material."),
    "CODEWORD_COMPARTMENT": ("Codeword / compartment",
        "A codeword, compartment, or programme nickname was found, indicating "
        "compartmented sensitive material."),
    "PII": ("Personal identifiers",
        "Personal identifiers were found (e.g. national ID, passport, date of birth, "
        "home address) that may not be permitted to leave."),
    "PHI": ("Health information",
        "Health or medical information was found."),
    "PCI_FINANCIAL": ("Financial / payment data",
        "Payment-card or financial-account data was found."),
    "SECRET_CREDENTIAL": ("Credential or secret",
        "A password, key, token, or other secret was found."),
    "INFRA_IDENTIFIER": ("Internal infrastructure detail",
        "Internal network or system identifiers were found (e.g. internal addresses, "
        "hostnames, system names)."),
    "PROPRIETARY_IP": ("Proprietary / privileged content",
        "Proprietary or privileged business content was found (e.g. source code, trade "
        "secrets, pre-release financials, NDA material)."),
    "OPSEC_CONTEXT": ("Operational content",
        "Operational or mission content was found that routine releasable material "
        "would not normally contain."),
    "SANITIZATION_RESIDUE": ("Incomplete sanitization",
        "Signs that cleaning was incomplete — for example a redaction marker next to "
        "un-redacted content, or a marking left in a header while the body was scrubbed."),
    "SENSITIVITY_SPIKE": ("Sensitivity spike",
        "One passage is markedly more sensitive than the rest of the document — the "
        "signature of a missed section or a block pasted in from a sensitive source."),
    "ENCODING_ANOMALY": ("Encoded / anomalous content",
        "The inspector observed encoded or non-linguistic content embedded in the text."),
    "PARSE_ERROR": ("Could not be inspected",
        "The item could not be parsed or inspected and is blocked as a precaution."),
}

_DEFAULT = ("Finding", "An item of interest was flagged during inspection.")


def explain(code):
    return EXPLAIN.get(code, _DEFAULT)
