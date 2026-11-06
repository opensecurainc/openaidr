"""Serve packaged or local console and admin single-page applications."""

import os
import re
from pathlib import Path
from starlette.responses import FileResponse, PlainTextResponse


def serve_app(name, relative=""):
    root = (
        Path(
            os.environ.get(
                "OPENAIDR_WEB_ROOT", Path(__file__).resolve().parents[1] / "web"
            )
        )
        / name
        / "dist"
    )
    if not (root / "index.html").is_file():
        root = Path(__file__).resolve().parents[3] / "apps" / name / "dist"
    index = root / "index.html"
    if not index.is_file():
        return PlainTextResponse(
            f"{name} web app was not built; run `make web`", status_code=404
        )
    candidate = (root / relative).resolve()
    if (
        candidate.is_relative_to(root.resolve())
        and candidate.is_file()
        and relative != "index.html"
    ):
        immutable = relative.startswith("assets/") or re.search(
            r"\.[\w-]{6,}\.[^.]+$", relative
        )
        return FileResponse(
            candidate,
            headers={
                "Cache-Control": "public, max-age=31536000, immutable"
                if immutable
                else "public, max-age=3600"
            },
        )
    return FileResponse(index, headers={"Cache-Control": "no-cache"})
