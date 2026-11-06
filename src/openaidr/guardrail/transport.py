"""Authenticated, bounded native provider mediation with original-origin routing.

Only the child receives the capability and temporary trust. Provider credentials
are forwarded in memory to their selected origin, never written to the journal.
"""

import asyncio
import base64
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime, timedelta, timezone
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import inspect
import ipaddress
import json
import os
from pathlib import Path
import secrets
import select
import socket
import ssl
from threading import BoundedSemaphore, Thread
import time
from urllib.parse import unquote, urlsplit
from urllib.request import proxy_bypass_environment

import httpx

from .native import NativeError


MAX_BODY = 32 * 1024 * 1024
MAX_CONNECTIONS = 8
_HOP = {"host", "connection", "proxy-authorization", "proxy-connection",
        "keep-alive", "transfer-encoding", "upgrade", "content-length"}


def _proxy(environment, url):
    parsed = urlsplit(url)
    proxies = {key.lower().removesuffix("_proxy"): value for key, value in environment.items()
               if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy") and value}
    if proxy_bypass_environment(parsed.netloc, proxies):
        return None
    value = proxies.get(parsed.scheme, proxies.get("all"))
    if value and urlsplit(value).scheme not in ("http", "https"):
        raise NativeError("unsupported_native_proxy")
    return value


def _ssl(environment, *, codex=False):
    if codex:
        context = ssl.create_default_context()
        if extra := environment.get("CODEX_CA_CERTIFICATE") or environment.get("SSL_CERT_FILE"):
            context.load_verify_locations(extra)
        return context
    context = ssl.create_default_context(cafile=environment.get("SSL_CERT_FILE") or None,
                                         capath=environment.get("SSL_CERT_DIR") or None)
    if extra := environment.get("NODE_EXTRA_CA_CERTS"):
        context.load_verify_locations(extra)
    return context


def request_payload(body, encoding):
    if encoding == "zstd":
        try:
            import zstandard
        except ImportError:
            raise NativeError("managed_compression_dependency_missing") from None
        with zstandard.ZstdDecompressor(max_window_size=MAX_BODY).stream_reader(body, read_across_frames=True) as reader:
            decoded = reader.read(MAX_BODY + 1)
        if len(decoded) > MAX_BODY:
            raise NativeError("oversized_native_body")
    elif encoding in (None, "", "identity"):
        decoded = body
    else:
        raise NativeError("unsupported_native_encoding")
    value = json.loads(decoded)
    if not isinstance(value, dict):
        raise NativeError("unsupported_native_body")
    return value


def certificate(directory, host, environment, *, codex=False):
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError:
        raise NativeError("managed_tls_dependency_missing") from None
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OpenAIDR temporary native transport")])
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    try:
        alternative = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        alternative = x509.DNSName(host)
    moment = datetime.now(timezone.utc)
    root = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer)
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(moment - timedelta(minutes=1)).not_valid_after(moment + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(root_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(moment - timedelta(minutes=1)).not_valid_after(moment + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([alternative]), critical=False)
            .sign(root_key, hashes.SHA256()))
    paths = [Path(directory) / item for item in ("native-ca.pem", "native-key.pem", "native-trust.pem", "native-server.pem")]
    data = root.public_bytes(serialization.Encoding.PEM)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    # NODE_EXTRA_CA_CERTS extends native roots. Retain an existing extra bundle.
    extra_path = (environment.get("CODEX_CA_CERTIFICATE") or environment.get("SSL_CERT_FILE")) if codex else environment.get("NODE_EXTRA_CA_CERTS")
    extra = Path(extra_path).read_bytes() if extra_path else b""
    for path, content in zip(paths, (data, private, extra + b"\n" + data, cert.public_bytes(serialization.Encoding.PEM))):
        with open(path, "xb", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
            stream.write(content)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(paths[3], paths[1])
    return context, paths


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, handler):
        self.slots = BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(("127.0.0.1", 0), handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, *_):
        # Never let socket/parser exceptions print provider headers or bodies.
        pass


class ProviderTransport:
    def __init__(self, session, upstream, *, connect=False):
        self.session, self.environment = session, session.environment
        self.loop = asyncio.get_running_loop()
        self.upstream = upstream.rstrip("/")
        self.origin = urlsplit(self.upstream)
        if (self.origin.scheme not in ("http", "https") or not self.origin.hostname
                or self.origin.username or self.origin.password or self.origin.query or self.origin.fragment):
            raise NativeError("unsupported_native_provider")
        if self.origin.scheme == "http" and self.origin.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise NativeError("unencrypted_native_provider")
        self.connect = connect
        self.capability = secrets.token_urlsafe(32)
        self.proxy_authorization = "Basic " + base64.b64encode(("openaidr:" + self.capability).encode()).decode()
        self.certificate_paths = []
        self.context = None
        if connect and self.origin.scheme == "https":
            self.context, self.certificate_paths = certificate(session.directory, self.origin.hostname, self.environment,
                                                                 codex=session.agent == "codex")
        self.connections = set()
        self.operations = set()
        self.closed = False
        self.server = _Server(self.handler())
        self.thread = Thread(target=self.server.serve_forever, name="managed-provider", daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}/{self.capability}" + self.origin.path

    @property
    def proxy_url(self):
        return f"http://openaidr:{self.capability}@127.0.0.1:{self.server.server_port}"

    def child_environment(self):
        result = {"HTTPS_PROXY": self.proxy_url, "https_proxy": self.proxy_url,
                  "HTTP_PROXY": self.proxy_url, "http_proxy": self.proxy_url,
                  "ALL_PROXY": self.proxy_url, "all_proxy": self.proxy_url}
        # Only the provider's NO_PROXY exception is overridden. The proxy
        # itself reapplies the original exclusions to all upstream traffic.
        result.update({"NO_PROXY": "", "no_proxy": ""})
        if self.certificate_paths:
            key = "CODEX_CA_CERTIFICATE" if self.session.agent == "codex" else "NODE_EXTRA_CA_CERTS"
            result[key] = str(self.certificate_paths[2])
        return result

    def wait(self, coro, connection=None):
        if self.closed:
            coro.close()
            raise NativeError("native_transport_abandoned")
        async def operation():
            task = asyncio.current_task()
            self.operations.add(task)
            try:
                if self.closed:
                    raise NativeError("native_transport_abandoned")
                return await coro
            finally:
                self.operations.discard(task)
                coro.close()
        future = asyncio.run_coroutine_threadsafe(operation(), self.loop)
        future.add_done_callback(lambda _: coro.close() if inspect.getcoroutinestate(coro) == inspect.CORO_CREATED else None)
        deadline = time.monotonic() + 570
        try:
            while not self.closed and time.monotonic() < deadline:
                try:
                    return future.result(timeout=.1)
                except FutureTimeout:
                    if connection and select.select([connection], [], [], 0)[0]:
                        previous = connection.gettimeout()
                        connection.settimeout(.01)
                        try:
                            # Native HTTP clients do not pipeline while waiting
                            # for a held response. EOF or unexpected new input
                            # abandons this callback before consent can release.
                            connection.recv(1)
                            raise NativeError("native_transport_abandoned")
                        except (TimeoutError, ssl.SSLWantReadError):
                            pass
                        finally:
                            connection.settimeout(previous)
            raise NativeError("native_transport_abandoned")
        except BaseException as exc:
            future.cancel()
            if isinstance(exc, NativeError) and exc.code == "native_transport_abandoned" and not self.closed:
                self.loop.call_soon_threadsafe(lambda: self.session.task(self.session.transport_abandoned()))
            raise

    def client(self, url):
        proxy = _proxy(self.environment, url)
        # Requests are handled by bounded worker threads. A client is scoped
        # to each request to avoid cross-thread mutable cookies/auth state.
        return httpx.Client(proxy=proxy, verify=_ssl(self.environment, codex=self.session.agent == "codex"), trust_env=False,
                            follow_redirects=False, timeout=httpx.Timeout(300, connect=15))

    def handler(self):
        owner = self
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            authenticated = False
            intercepted = False

            def log_message(self, *_):
                pass

            def setup(self):
                super().setup()
                self.connection.settimeout(600)
                owner.connections.add(self.connection)

            def finish(self):
                owner.connections.discard(self.connection)
                try:
                    super().finish()
                except OSError:
                    pass

            def reply(self, status, data, headers=()):
                self.send_response(status)
                for key, value in headers:
                    if key.lower() not in _HOP | {"content-encoding"}:
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)
                self.wfile.flush()
                self.close_connection = True

            def reject(self, status=403):
                self.reply(status, b'{"error":"managed transport unavailable"}', [("Content-Type", "application/json")])

            def authorized(self):
                return hmac.compare_digest(self.headers.get("Proxy-Authorization", ""), owner.proxy_authorization)

            def do_CONNECT(self):
                if not owner.connect or self.headers.get("Origin") or not self.authorized():
                    return self.reject(407)
                target = urlsplit("https://" + self.path)
                if not target.hostname or target.username or target.path or target.query or target.fragment:
                    return self.reject()
                if (target.hostname, target.port or 443) != (owner.origin.hostname, owner.origin.port or 443):
                    return self.tunnel(target.hostname, target.port or 443)
                self.send_response(200, "Connection established")
                self.end_headers()
                self.wfile.flush()
                try:
                    old = self.connection
                    self.connection = owner.context.wrap_socket(self.connection, server_side=True)
                    owner.connections.discard(old)
                    owner.connections.add(self.connection)
                    self.rfile = self.connection.makefile("rb")
                    self.wfile = self.connection.makefile("wb")
                    self.authenticated = self.intercepted = True
                    self.close_connection = False
                    self.handle_one_request()
                except (OSError, ValueError):
                    self.close_connection = True

            def tunnel(self, host, port):
                upstream = None
                try:
                    original = _proxy(owner.environment, f"https://{host}:{port}")
                    if original:
                        proxy = urlsplit(original)
                        upstream = socket.create_connection((proxy.hostname, proxy.port or (443 if proxy.scheme == "https" else 80)), 15)
                        if proxy.scheme == "https":
                            upstream = _ssl(owner.environment, codex=owner.session.agent == "codex").wrap_socket(upstream, server_hostname=proxy.hostname)
                        auth = ""
                        if proxy.username is not None:
                            value = unquote(proxy.username) + ":" + unquote(proxy.password or "")
                            auth = "Proxy-Authorization: Basic " + base64.b64encode(value.encode()).decode() + "\r\n"
                        upstream.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}\r\n".encode())
                        header = bytearray()
                        while not header.endswith(b"\r\n\r\n") and len(header) < 65536:
                            chunk = upstream.recv(1)
                            if not chunk:
                                raise OSError("proxy closed")
                            header.extend(chunk)
                        if b" 200 " not in bytes(header).split(b"\r\n", 1)[0]:
                            return self.reject(502)
                    else:
                        upstream = socket.create_connection((host, port), 15)
                    self.send_response(200, "Connection established")
                    self.end_headers()
                    self.wfile.flush()
                    while not owner.closed:
                        readable, _, _ = select.select([upstream, self.connection], [], [], 1)
                        for source in readable:
                            data = source.recv(65536)
                            if not data:
                                return
                            (upstream if source is self.connection else self.connection).sendall(data)
                except OSError:
                    pass
                finally:
                    self.close_connection = True
                    if upstream:
                        upstream.close()

            def route(self):
                if self.headers.get("Origin"):
                    raise NativeError("foreign_transport_origin")
                if owner.connect:
                    if self.intercepted:
                        if not self.path.startswith("/") or self.path.startswith("//"):
                            raise NativeError("foreign_transport_origin")
                        return f"{owner.origin.scheme}://{owner.origin.netloc}" + self.path
                    if not self.authorized():
                        raise NativeError("transport_authentication_required")
                    target = urlsplit(self.path)
                    if target.scheme != "http" or not target.hostname or target.username or target.password:
                        raise NativeError("foreign_transport_origin")
                    return self.path
                prefix = "/" + owner.capability
                if not self.path.startswith(prefix + "/"):
                    raise NativeError("transport_authentication_required")
                path = self.path[len(prefix):]
                # Keep the chosen provider path and credentials on one origin.
                if not path.startswith(owner.origin.path + "/"):
                    raise NativeError("foreign_transport_origin")
                return f"{owner.origin.scheme}://{owner.origin.netloc}" + path

            def forward(self):
                before = after = None
                try:
                    url = self.route()
                    if self.headers.get("Upgrade"):
                        # No websocket was accepted. The pinned Codex client
                        # retains its tested HTTP fallback and native settings.
                        return self.reject(426)
                    if self.headers.get("Transfer-Encoding"):
                        return self.reject(411)
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 0 or length > MAX_BODY:
                        return self.reject(413)
                    body = self.rfile.read(length)
                    if len(body) != length:
                        raise NativeError("incomplete_native_body")
                    target = urlsplit(url)
                    selected = (target.scheme, target.netloc) == (owner.origin.scheme, owner.origin.netloc)
                    inference = selected and self.command == "POST" and target.path.rstrip("/").endswith(("/responses", "/messages"))
                    payload = request_payload(body, self.headers.get("Content-Encoding")) if inference else None
                    if inference:
                        if not isinstance(payload, dict):
                            raise NativeError("unsupported_native_body")
                        before = owner.wait(owner.session.provider_request(payload), self.connection)
                    if owner.closed or owner.session.process.returncode is not None:
                        raise NativeError("native_transport_abandoned")
                    headers = {key: value for key, value in self.headers.items() if key.lower() not in _HOP}
                    with owner.client(url) as client, client.stream(self.command, url, content=body, headers=headers) as response:
                        if inference and 300 <= response.status_code < 400:
                            raise NativeError("unsupported_provider_redirect")
                        data = bytearray()
                        for chunk in response.iter_bytes():
                            if len(data) + len(chunk) > MAX_BODY:
                                raise NativeError("oversized_provider_body")
                            data.extend(chunk)
                        if before:
                            owner.wait(before.finish("succeeded"))
                            before = None
                        if inference and 200 <= response.status_code < 300 and not owner.session.auxiliary_request(payload):
                            after = owner.wait(owner.session.provider_response(bytes(data), response.headers.get("content-type", "")), self.connection)
                        self.reply(response.status_code, bytes(data), response.headers.multi_items())
                        if after:
                            owner.wait(after.finish("succeeded"))
                            after = None
                except Exception:
                    for batch in (before, after):
                        if batch:
                            try:
                                owner.wait(batch.finish("uncertain"))
                            except Exception:
                                pass
                    try:
                        self.reject(502)
                    except OSError:
                        pass

            do_POST = do_GET = do_PUT = do_PATCH = do_DELETE = do_HEAD = forward
        return Handler

    async def close(self):
        self.closed = True
        failed = False
        for connection in tuple(self.connections):
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                failed = True
        for operation in (self.server.shutdown, self.server.server_close, lambda: self.thread.join(3)):
            try:
                await asyncio.to_thread(operation)
            except OSError:
                failed = True
        # Native socket workers may still be unwinding bounded upstream I/O.
        # They cannot schedule new gate work after closed, and all operations
        # that already entered the event loop are cancelled and joined here.
        while self.operations:
            active = tuple(self.operations)
            for task in active:
                task.cancel()
            await asyncio.gather(*active, return_exceptions=True)
        for path in self.certificate_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                failed = True
        if failed:
            raise NativeError("native_shutdown_failed")


def completed_response(data, content_type, product):
    """Parse only complete provider messages. No incomplete frame is released."""
    if "text/event-stream" not in content_type:
        value = json.loads(data)
        if not isinstance(value, dict):
            raise NativeError("unsupported_provider_response")
        return value
    frames = []
    for block in data.replace(b"\r\n", b"\n").split(b"\n\n"):
        lines = [line[5:].lstrip() for line in block.split(b"\n") if line.startswith(b"data:")]
        if lines and b"\n".join(lines) != b"[DONE]":
            frames.append(json.loads(b"\n".join(lines)))
    if product == "codex":
        values = [frame["response"] for frame in frames if frame.get("type") == "response.completed"]
        if len(values) != 1:
            raise NativeError("incomplete_provider_response")
        return values[0]
    message = None
    blocks = {}
    finished = False
    for frame in frames:
        kind = frame.get("type")
        if kind == "message_start":
            message = frame["message"]
        elif kind == "content_block_start":
            blocks[frame["index"]] = frame["content_block"]
        elif kind == "content_block_delta":
            block = blocks[frame["index"]]
            delta = frame["delta"]
            if delta.get("type") == "text_delta":
                block["text"] = block.get("text", "") + delta["text"]
            elif delta.get("type") == "input_json_delta":
                block["_input_json"] = block.get("_input_json", "") + delta["partial_json"]
        elif kind == "message_stop":
            finished = True
    if not message or not finished:
        raise NativeError("incomplete_provider_response")
    message["content"] = [blocks[key] for key in sorted(blocks)]
    for block in message["content"]:
        if "_input_json" in block:
            block["input"] = json.loads(block.pop("_input_json"))
    return message
