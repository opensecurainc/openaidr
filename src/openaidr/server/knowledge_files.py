"""Bounded text extraction for company knowledge uploads."""

import base64
import binascii
import hashlib
import io
import json
from pathlib import PurePath
import subprocess
import sys
import zipfile

from .httpx import APIError, require
from .knowledge import _text
from . import knowledge_library

MAX_FILE_BYTES = 5 << 20
MAX_TEXT_BYTES = 256 << 10
EXTENSIONS = {".md", ".markdown", ".txt", ".pdf", ".docx"}


def extract(filename, content):
    suffix = PurePath(filename).suffix.lower()
    require(suffix in EXTENSIONS, "Use a Markdown, text, PDF, or Word (.docx) file", 415)
    require(0 < len(content) <= MAX_FILE_BYTES, "Upload a nonempty file no larger than 5 MiB", 413)
    if suffix in {".md", ".markdown", ".txt"}:
        try:
            text = content.decode("utf-8-sig")
        except UnicodeError:
            raise APIError(400, "Text files must use UTF-8 encoding") from None
    elif suffix == ".pdf":
        from pypdf import PdfReader

        require(content.startswith(b"%PDF-"), "The file is not a PDF")
        reader = PdfReader(io.BytesIO(content))
        require(not reader.is_encrypted, "Upload a PDF without password protection")
        require(len(reader.pages) <= 200, "PDF files must have at most 200 pages")
        pages, size = [], 0
        for page in reader.pages:
            value = page.extract_text() or ""
            size += len(value.encode()) + 2
            require(size <= MAX_TEXT_BYTES, "Extracted text exceeds 256 KiB", 413)
            pages.append(value)
        text = "\n\n".join(pages)
        require(text.strip(), "This PDF has no extractable text. Upload a text-based PDF; OCR is not supported")
    else:
        from docx import Document
        from docx.table import Table
        from docx.text.paragraph import Paragraph

        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            entries = archive.infolist()
            require(len(entries) <= 1000 and sum(e.file_size for e in entries) <= 16 << 20,
                    "The Word file expands beyond the import limit", 413)
        document = Document(io.BytesIO(content))
        lines, size = [], 0

        def blocks(container):
            nonlocal size
            for block in container.iter_inner_content():
                if isinstance(block, Paragraph):
                    lines.append(block.text)
                    size += len(block.text.encode()) + 2
                elif isinstance(block, Table):
                    for row in block.rows:
                        # Merged cells can repeat in row.cells. Keep each once.
                        seen = set()
                        for cell in row.cells:
                            if cell._tc not in seen:
                                seen.add(cell._tc)
                                blocks(cell)
                require(size <= MAX_TEXT_BYTES,
                        "Extracted text exceeds 256 KiB", 413)

        blocks(document)
        text = "\n\n".join(lines)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    _text({"text": text}, "text", MAX_TEXT_BYTES)
    require(not any(ord(char) < 32 and char not in "\n\t" for char in text),
            "Document contains unsupported control characters")
    return text


def upload(st, tenant, data):
    require(set(data) == {"revision", "filename", "content", "keywords"}, "invalid upload fields")
    filename = _text(data, "filename", 240)
    require("/" not in filename and "\\" not in filename, "filename must not contain a path")
    require(PurePath(filename).suffix.lower() in EXTENSIONS,
            "Use a Markdown, text, PDF, or Word (.docx) file", 415)
    require(isinstance(data["content"], str) and len(data["content"]) <= ((MAX_FILE_BYTES + 2) // 3) * 4,
            "File exceeds 5 MiB", 413)
    try:
        content = base64.b64decode(data["content"], validate=True)
    except (ValueError, binascii.Error):
        raise APIError(400, "File content must be base64") from None
    require(0 < len(content) <= MAX_FILE_BYTES, "Upload a nonempty file no larger than 5 MiB", 413)
    require(isinstance(data["keywords"], list) and len(data["keywords"]) <= 32, "invalid keywords")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "openaidr.server.knowledge_files", filename], input=content,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=False,
        )
        require(result.returncode == 0, "The document could not be parsed within the import limits")
        parsed = json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        raise APIError(400, "Document extraction exceeded 15 seconds") from None
    except (OSError, ValueError):
        raise APIError(503, "Document extraction is unavailable") from None
    if "error" in parsed:
        raise APIError(parsed.get("status", 400), parsed["error"])
    ident = "upload:" + hashlib.sha256(filename.casefold().encode()).hexdigest()[:32]
    return knowledge_library.import_document(st, tenant, {
        "revision": data["revision"], "source_id": ident,
        "source_version": hashlib.sha256(content + json.dumps(
            {"filename": filename, "keywords": data["keywords"]}, sort_keys=True,
        ).encode()).hexdigest(), "title": filename,
        "source_uri": "wiki://uploads/" + ident, "scope_key": "", "kind": "reference",
        "markdown": parsed["text"], "freshness_seconds": 86400,
        "keys": [{"key_type": "term", "lookup_value": word, "canonical_key": ident}
                 for word in data["keywords"]],
    })


if __name__ == "__main__":
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (12, 12))
        if sys.platform.startswith("linux"):
            resource.setrlimit(resource.RLIMIT_AS, (768 << 20, 768 << 20))
        value = {"text": extract(sys.argv[1], sys.stdin.buffer.read(MAX_FILE_BYTES + 1))}
    except APIError as error:
        value = {"error": error.message, "status": error.status}
    except ImportError:
        value = {"error": "Document parsers are unavailable. Install the server dependencies", "status": 503}
    except Exception:
        value = {"error": "Invalid or unsupported document"}
    print(json.dumps(value))
