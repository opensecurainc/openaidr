"""Bounded MCP knowledge access with pinned network destinations."""

import asyncio
import base64
from contextlib import asynccontextmanager
import ipaddress
import socket
from urllib.parse import parse_qsl, urlsplit

import anyio
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from uritemplate import URITemplate

from .httpx import APIError, require
from .knowledge import _text
from openaidr.core.redact import redact_value
from .knowledge_mcp_imports import selection, selection_key, tool_content, tool_hash, tool_readable, tool_title

MAX_RESPONSE = 1 << 20
MAX_RESOURCES = 200


def endpoint(value, private_origins):
    _text({"endpoint": value}, "endpoint", 1024)
    try:
        parsed = urlsplit(value)
        url = httpx2.URL(value)
        valid = (
            parsed.scheme in ("http", "https")
            and bool(parsed.hostname)
            and not parsed.username
            and not parsed.password
            and not parsed.fragment
            and not any(_credential_query(k) for k, _ in parse_qsl(parsed.query))
            and not any(ord(c) < 33 for c in value)
            and "\\" not in value
            and parsed.port != 0
        )
    except (ValueError, httpx2.InvalidURL):
        valid = False
    require(
        valid and redact_value(value) == value,
        "Use an HTTP MCP endpoint without credentials or a fragment",
    )
    origin = str(url.copy_with(path="", query=None, fragment=None)).rstrip("/")
    private = origin in {
        item.strip().rstrip("/") for item in private_origins.split(",") if item.strip()
    }
    require(
        url.scheme == "https" or private,
        "MCP requires HTTPS. An operator must allow an exact origin for private HTTP servers",
    )
    return url, private


def _credential_query(key):
    return any(part in key.lower() for part in ("token", "secret", "password", "credential", "api_key", "apikey", "authorization", "signature"))


class LimitedStream(httpx2.AsyncByteStream):
    def __init__(self, stream):
        self.stream = stream

    async def __aiter__(self):
        size = 0
        async for chunk in self.stream:
            size += len(chunk)
            require(size <= MAX_RESPONSE, "MCP response exceeds 1 MiB", 502)
            yield chunk

    async def aclose(self):
        await self.stream.aclose()


class PinnedTransport(httpx2.AsyncBaseTransport):
    def __init__(self, url, address):
        self.url, self.address = url, address
        self.transport = httpx2.AsyncHTTPTransport(trust_env=False, retries=0)

    async def handle_async_request(self, request):
        # SDK redirects, session traffic, and reconnects must use the same endpoint.
        require(
            request.url == self.url,
            "MCP redirects are not supported; use the final endpoint URL",
            502,
        )
        pinned = httpx2.Request(
            request.method,
            request.url.copy_with(host=self.address),
            headers=request.headers,
            stream=request.stream,
            extensions={**request.extensions, "sni_hostname": self.url.host},
        )
        response = await self.transport.handle_async_request(pinned)
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            await response.aclose()
            raise APIError(502, "MCP compressed responses are not supported")
        response.stream = LimitedStream(response.stream)
        return response

    async def aclose(self):
        await self.transport.aclose()


async def _pages(method, field, limit=500):
    items, cursor, cursors = [], None, set()
    for _ in range(20):
        page = await method(cursor=cursor, cache_mode="bypass")
        items.extend(getattr(page, field))
        require(len(items) <= limit, "MCP discovery exceeds its item limit; use a smaller collection", 502)
        cursor = page.next_cursor
        if not cursor:
            return items
        require(cursor not in cursors, "MCP discovery pagination did not advance", 502)
        cursors.add(cursor)
    raise APIError(502, "MCP discovery pagination exceeds 20 pages")


async def _catalog(client):
    resources, templates, tools = [], [], []
    capabilities = client.server_capabilities
    if capabilities.resources:
        for item in await _pages(client.list_resources, "resources", MAX_RESOURCES):
            uri = _text({"uri": str(item.uri)}, "uri", 1024)
            require(
                redact_value(uri) == uri,
                "MCP resource identifiers must not contain credentials",
                502,
            )
            parsed = urlsplit(uri)
            require(
                not parsed.username and not parsed.password,
                "MCP resource identifiers must not contain credentials",
                502,
            )
            name = _text({"name": item.title or item.name}, "name", 240)
            resources.append(
                {"uri": uri, "name": name, "mime_type": item.mime_type or ""}
            )
        for item in await _pages(client.list_resource_templates, "resource_templates"):
            uri = _text({"uri": item.uri_template}, "uri", 1024)
            require(redact_value(uri) == uri and "@" not in urlsplit(uri).netloc,
                    "MCP template identifiers must not contain credentials", 502)
            templates.append({
                "uri_template": uri, "name": _text({"name": item.title or item.name}, "name", 240),
                "description": item.description or "", "parameters": list(URITemplate(item.uri_template).variable_names),
            })
    if capabilities.tools:
        tools = await _pages(client.list_tools, "tools")
    require(len({r["uri"] for r in resources}) == len(resources), "MCP server returned duplicate resources", 502)
    require(len({t["uri_template"] for t in templates}) == len(templates), "MCP server returned duplicate templates", 502)
    require(len({t.name for t in tools}) == len(tools), "MCP server returned duplicate tools", 502)
    return {"resources": resources, "templates": templates, "tools": [{
        "name": t.name, "title": t.title or t.name, "description": t.description or "",
        "input_schema": t.input_schema, "schema_hash": tool_hash(t), "can_import": tool_readable(t),
    } for t in tools]}


async def _read(client, catalog, source):
    selection(source)
    kind = source["kind"]
    if kind == "tool":
        tool = next((t for t in catalog["tools"] if t["name"] == source["name"]), None)
        require(tool is not None, "The selected MCP tool is no longer available", 409)
        require(tool["can_import"], "Tools marked as modifying data cannot be used for knowledge imports", 400)
        require(tool["schema_hash"] == source["schema_hash"], "The MCP tool definition changed; select it again", 409)
        # Do not automatically re-list and retry a changed tool or answer input requests.
        result = await client.session.call_tool(source["name"], source["arguments"])
        text = tool_content(result)
        name = tool_title(result, text, tool["title"])
    else:
        uri = source.get("uri")
        if kind == "template":
            template = next((t for t in catalog["templates"] if t["uri_template"] == source["uri_template"]), None)
            require(template is not None, "The selected MCP template is no longer available", 409)
            require(set(source["parameters"]) <= set(template["parameters"]), "Unknown MCP template parameter")
            uri = URITemplate(source["uri_template"]).expand(**source["parameters"])
            name = template["name"]
        else:
            resource = next((r for r in catalog["resources"] if r["uri"] == uri), None)
            require(resource is not None, "A selected MCP resource is no longer listed; select resources again", 409)
            name = resource["name"]
        _text({"uri": uri}, "uri", 1024)
        result = await client.read_resource(uri, cache_mode="bypass")
        require(bool(result.contents) and all(hasattr(c, "text") for c in result.contents), "Only MCP text resources can be imported", 415)
        text = "\n\n".join(c.text for c in result.contents)
    _text({"text": text}, "text", 256 << 10)
    return {"uri": selection_key(source), "name": _text({"name": name}, "name", 240), "text": text}


def auth_headers(credentials):
    if isinstance(credentials, str):
        credentials = {"type": "bearer", "token": credentials} if credentials else {"type": "none"}
    kind = credentials["type"]
    if kind == "bearer":
        return {"Authorization": "Bearer " + credentials["token"]}
    if kind == "basic":
        encoded = base64.b64encode((credentials["username"] + ":" + credentials["password"]).encode()).decode()
        return {"Authorization": "Basic " + encoded}
    if kind == "header":
        return {credentials["name"]: credentials["value"]}
    return {}


@asynccontextmanager
async def session(url, private, credentials):
    with anyio.fail_after(25):
        addresses = await anyio.to_thread.run_sync(
            lambda: socket.getaddrinfo(
                url.host,
                url.port or (443 if url.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            ),
            abandon_on_cancel=True,
        )
        require(bool(addresses), "MCP hostname did not resolve", 502)
        ips = [ipaddress.ip_address(item[4][0]) for item in addresses]
        require(
            all(
                not (ip.is_link_local or ip.is_unspecified or ip.is_multicast)
                and (not ip.is_reserved or ip.is_loopback)
                and (ip.is_global or (private and (ip.is_loopback or ip.is_private)))
                for ip in ips
            ),
            "MCP address is not allowed. An operator must allow the exact origin for a private server",
            400,
        )
        headers = {"Accept-Encoding": "identity", **auth_headers(credentials)}
        async with httpx2.AsyncClient(
            transport=PinnedTransport(url, str(ips[0])),
            headers=headers,
            timeout=10,
            trust_env=False,
            follow_redirects=False,
        ) as http:
            async with Client(
                streamable_http_client(
                    str(url),
                    http_client=http,
                    terminate_on_close=True,
                    max_sse_event_size=MAX_RESPONSE,
                ),
                input_required_max_rounds=0,
            ) as client:
                yield client


async def _run(url, private, credentials, sources):
    async with session(url, private, credentials) as client:
        catalog = await _catalog(client)
        if sources is None:
            return catalog
        documents, total = [], 0
        for source in sources:
            doc = await _read(client, catalog, source)
            total += len(doc["text"].encode())
            require(total <= 2 << 20, "Selected MCP content exceeds 2 MiB of text", 413)
            documents.append(doc)
        return documents


def run(value, credentials, private_origins, sources=None):
    url, private = endpoint(value, private_origins)
    try:
        return asyncio.run(_run(url, private, credentials, sources))
    except APIError:
        raise
    except Exception as error:
        # SDK task groups wrap boundary errors. Preserve safe, local messages only.
        pending = [error]
        while pending:
            item = pending.pop()
            if isinstance(item, APIError):
                raise item from None
            pending.extend(getattr(item, "exceptions", ()))
        raise APIError(
            502,
            "Unable to access the MCP server. Check the endpoint, authentication, permissions, and server availability",
        ) from None
