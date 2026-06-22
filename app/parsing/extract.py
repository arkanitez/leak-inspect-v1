"""Extract text from uploads as provenance-tagged segments.

A *segment* is {"provenance": <where in the document>, "text": <str>}. Provenance
matters: a SECRET banner in a header or a name in a tracked-change deletion is the
exact accidental-leakage signal this pipeline exists to catch, so we extract every
text stream, not just the visible body.

OOXML files are ZIP containers; we parse their XML parts with defusedxml to block
XXE / billion-laughs, and enforce entry-count and uncompressed-size caps against
decompression bombs. Legacy binary .doc/.xls/.ppt and scanned (image-only) PDFs are
flagged as out-of-scope rather than silently producing empty text.
"""
import io
import zipfile

from defusedxml.ElementTree import fromstring as safe_fromstring

from ..config import cfg

# OOXML text-bearing element local-names (namespace-agnostic):
#   w:t / a:t / <t>  -> visible text in Word, PowerPoint, and the xlsx string table
#   w:delText        -> text removed by a tracked-change deletion (still in the file!)
TEXT_TAGS = {"t", "delText"}
DEL_TAGS = {"delText"}


def _localname(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def detect_format(filename, data):
    name = (filename or "").lower()
    if name.endswith(".docx"):
        return "docx"
    if name.endswith(".xlsx"):
        return "xlsx"
    if name.endswith(".pptx"):
        return "pptx"
    if name.endswith(".pdf"):
        return "pdf"
    if name.endswith((".txt", ".md", ".csv", ".log", ".json", ".xml", ".html", ".rtf")):
        return "txt"
    # Legacy binary office formats are not OOXML ZIPs.
    if name.endswith((".doc", ".xls", ".ppt")):
        return "legacy_office"
    # Content sniff.
    if data[:4] == b"%PDF":
        return "pdf"
    if data[:2] == b"PK":
        return "ooxml_zip"   # resolved below by inspecting parts
    return "txt"


def _provenance_for(part):
    p = part.lower()
    if p == "word/document.xml":
        return "Body"
    if p.startswith("word/header"):
        return "Header"
    if p.startswith("word/footer"):
        return "Footer"
    if p == "word/comments.xml":
        return "Comments"
    if p in ("word/footnotes.xml", "word/endnotes.xml"):
        return "Footnotes/endnotes"
    if p.startswith("ppt/slides/slide"):
        return "Slide"
    if p.startswith("ppt/notesslides/"):
        return "Speaker notes"
    if "comment" in p:
        return "Comments"
    if p == "xl/sharedstrings.xml":
        return "Cell values"
    if p.startswith("xl/worksheets/"):
        return "Worksheet (inline)"
    if p.startswith("docprops/"):
        return "Document properties"
    return "Other (%s)" % part


def _zip_safe_open(data):
    zf = zipfile.ZipFile(io.BytesIO(data))
    infos = zf.infolist()
    if len(infos) > cfg.MAX_ZIP_ENTRIES:
        raise ValueError("archive has too many entries (%d)" % len(infos))
    total = sum(i.file_size for i in infos)
    if total > cfg.MAX_DECOMPRESS_BYTES:
        raise ValueError("archive uncompressed size exceeds cap (%d bytes)" % total)
    return zf, infos


def _extract_xml_text(xml_bytes):
    """Return (visible_text, deleted_text) collected from one XML part."""
    try:
        root = safe_fromstring(xml_bytes)
    except Exception:
        return "", ""
    visible, deleted = [], []
    for el in root.iter():
        ln = _localname(el.tag)
        if ln in TEXT_TAGS and el.text:
            (deleted if ln in DEL_TAGS else visible).append(el.text)
    return "".join(visible), " ".join(deleted)


def parse_ooxml(data):
    zf, infos = _zip_safe_open(data)
    parts = {i.filename for i in infos}
    # Resolve which OOXML flavour (for the format label).
    if "word/document.xml" in parts:
        fmt = "docx"
    elif any(p.startswith("ppt/slides/") for p in parts):
        fmt = "pptx"
    elif "xl/workbook.xml" in parts:
        fmt = "xlsx"
    else:
        fmt = "ooxml"

    # Group text by provenance. Slides are numbered individually.
    grouped = {}     # provenance -> list[str]
    del_grouped = {}
    for info in infos:
        name = info.filename
        ln = name.lower()
        if not ln.endswith(".xml"):
            continue
        if not (ln.startswith("word/") or ln.startswith("ppt/")
                or ln.startswith("xl/") or ln.startswith("docprops/")):
            continue
        try:
            xml = zf.read(info)
        except Exception:
            continue
        vis, dele = _extract_xml_text(xml)
        if not vis and not dele:
            continue
        prov = _provenance_for(name)
        if prov == "Slide":
            num = "".join(ch for ch in name if ch.isdigit()) or "?"
            prov = "Slide %s" % num
        grouped.setdefault(prov, []).append(vis)
        if dele.strip():
            del_grouped.setdefault("Tracked-change deletion (%s)" % prov, []).append(dele)

    segments = []
    for prov, chunks in grouped.items():
        text = "\n".join(t for t in chunks if t.strip())
        if text.strip():
            segments.append({"provenance": prov, "text": text})
    for prov, chunks in del_grouped.items():
        text = "\n".join(t for t in chunks if t.strip())
        if text.strip():
            segments.append({"provenance": prov, "text": text})
    return fmt, segments


def parse_pdf(data):
    try:
        from pypdf import PdfReader
    except Exception:
        return "pdf", [{"provenance": "PDF", "text": ""}], "pypdf not installed"
    segments = []
    note = None
    try:
        reader = PdfReader(io.BytesIO(data))
        # Document metadata.
        meta = reader.metadata or {}
        meta_text = " ".join(str(v) for v in meta.values() if v)
        if meta_text.strip():
            segments.append({"provenance": "Document properties", "text": meta_text})
        total_text = 0
        for n, page in enumerate(reader.pages, 1):
            try:
                t = page.extract_text() or ""
            except Exception:
                t = ""
            total_text += len(t.strip())
            if t.strip():
                segments.append({"provenance": "Page %d" % n, "text": t})
        if total_text == 0:
            note = "no extractable text — likely scanned/image-only (OCR out of scope)"
    except Exception as e:
        return "pdf", segments, "PDF parse error: %s" % e
    return "pdf", segments, note


def parse_text(data):
    text = data.decode("utf-8", errors="replace")
    return "txt", [{"provenance": "Text", "text": text}]


def extract(filename, data):
    """Dispatch. Returns (fmt, segments, note). `note` is a human-readable caveat
    or None; an empty `segments` with a note means 'parsed but nothing usable'."""
    fmt = detect_format(filename, data)
    if fmt == "legacy_office":
        return "legacy_office", [], ("legacy binary Office format (.doc/.xls/.ppt) "
                                     "not supported — re-save as .docx/.xlsx/.pptx")
    if fmt == "pdf":
        return parse_pdf(data)
    if fmt in ("docx", "xlsx", "pptx", "ooxml_zip"):
        try:
            f, segs = parse_ooxml(data)
            return f, segs, None
        except ValueError as e:
            return "ooxml", [], "rejected: %s" % e
        except Exception as e:
            return "ooxml", [], "OOXML parse error: %s" % e
    f, segs = parse_text(data)
    return f, segs, None
