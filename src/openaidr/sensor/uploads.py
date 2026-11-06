"""Send large retained payloads as separate requests below proxy body limits."""

import hashlib
import uuid


CHUNK_BYTES = 768 << 10
INGEST_PATHS = {"events", "inventory/applications", "inventory/snapshots",
                "inventory/skills/manifest", "inventory/skills/content"}


def post(client, url, content, *, chunk_url, headers=None, **options):
    if len(content) <= CHUNK_BYTES:
        return client.post(url, content=content, headers=headers, **options)
    upload_headers = {
        **(headers or {}),
        "X-OpenAIDR-Upload-Id": str(uuid.uuid4()),
        "X-OpenAIDR-Upload-Length": str(len(content)),
        "X-OpenAIDR-Upload-SHA256": hashlib.sha256(content).hexdigest(),
    }
    for offset in range(0, len(content), CHUNK_BYTES):
        chunk = content[offset:offset + CHUNK_BYTES]
        response = client.post(chunk_url, content=chunk, headers={
            **upload_headers, "X-OpenAIDR-Upload-Offset": str(offset),
        }, **options)
        if not response.is_success:
            return response
        if offset + len(chunk) == len(content):
            if response.headers.get("x-openaidr-upload-complete") != "1":
                raise ValueError("server did not confirm the complete upload")
            return response
        if (response.status_code != 202
                or response.headers.get("x-openaidr-upload-offset") != str(offset + len(chunk))):
            raise ValueError("server did not acknowledge the upload fragment")
