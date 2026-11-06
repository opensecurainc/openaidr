"""HTTP listeners that bind numeric loopback addresses without DNS discovery."""

import ipaddress
import hmac
import io
from http.client import parse_headers
import socket
import selectors
import time
from http.server import HTTPServer
from socketserver import TCPServer, ThreadingMixIn
from threading import BoundedSemaphore
from urllib.parse import urlsplit


class BoundedThreadingMixIn(ThreadingMixIn):
    max_requests = 8

    def __init__(self, *args, **kwargs):
        self.request_slots = BoundedSemaphore(self.max_requests)
        super().__init__(*args, **kwargs)

    def process_request(self, request, address):
        # Admit before creating a worker or reading any headers or body. Queuing
        # parsed requests here would retain their payloads while storage is busy.
        if not self.request_slots.acquire(blocking=False):
            self.reject_request(request, b"503 Service Unavailable")
            return
        try:
            # Incomplete local requests cannot hold every worker indefinitely.
            request.settimeout(10)
            super().process_request(request, address)
        except BaseException:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.request_slots.release()

    def reject_request(self, request, status):
        try:
            request.setblocking(False)
            request.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Length: 0\r\n"
                            b"Retry-After: 5\r\nConnection: close\r\n\r\n")
        except OSError:
            pass
        finally:
            self.shutdown_request(request)


class HookAdmissionMixIn:
    """Wait for authenticated headers without occupying hook worker slots."""

    header_bytes = 64 << 10
    idle_connections = 64
    request_queue_size = 64
    token = None

    def __init__(self, *args, **kwargs):
        self.readable = selectors.DefaultSelector()
        self.waiting = {}
        super().__init__(*args, **kwargs)

    def process_request(self, request, address):
        if len(self.waiting) >= self.idle_connections:
            oldest = next(iter(self.waiting))
            self.remove_waiter(oldest)
            self.reject_request(oldest, b"503 Service Unavailable")
        request.setblocking(False)
        self.readable.register(request, selectors.EVENT_READ)
        self.waiting[request] = (address, time.monotonic() + 2)

    def remove_waiter(self, request):
        self.readable.unregister(request)
        return self.waiting.pop(request)[0]

    def service_actions(self):
        # Winsock select rejects empty descriptor sets.
        for key, _ in self.readable.select(0) if self.waiting else ():
            request = key.fileobj
            try:
                # Peek leaves the original bytes for BaseHTTPRequestHandler.
                data = request.recv(self.header_bytes + 1, socket.MSG_PEEK)
                head, separator, _ = data.partition(b"\r\n\r\n")
                if not data:
                    self.remove_waiter(request)
                    self.shutdown_request(request)
                elif len(head) > self.header_bytes:
                    self.remove_waiter(request)
                    self.reject_request(request, b"431 Request Header Fields Too Large")
                elif separator:
                    address = self.remove_waiter(request)
                    headers = parse_headers(io.BytesIO(head.partition(b"\r\n")[2] + b"\r\n\r\n"))
                    if self.token and not hmac.compare_digest(
                        headers.get("Authorization", "").encode(), ("Bearer " + self.token).encode()
                    ):
                        self.reject_request(request, b"401 Unauthorized")
                    else:
                        super().process_request(request, address)
            except BlockingIOError:
                continue
            except Exception:
                if request in self.waiting:
                    self.remove_waiter(request)
                self.shutdown_request(request)
        for request, (_, deadline) in list(self.waiting.items()):
            if time.monotonic() >= deadline:
                self.remove_waiter(request)
                self.shutdown_request(request)
        super().service_actions()

    def serve_forever(self, poll_interval=0.05):
        super().serve_forever(poll_interval=poll_interval)

    def server_close(self):
        for request in list(self.waiting):
            self.remove_waiter(request)
            self.shutdown_request(request)
        self.readable.close()
        super().server_close()


class LoopbackHTTPServer(BoundedThreadingMixIn, HTTPServer):
    daemon_threads = True

    def __init__(self, address, handler):
        host = ipaddress.ip_address(address[0])
        if not host.is_loopback:
            raise ValueError("listener must bind to a loopback address")
        self.address_family = socket.AF_INET6 if host.version == 6 else socket.AF_INET
        super().__init__(address, handler)

    def server_bind(self):
        # HTTPServer calls getfqdn here. Local hook and OTLP receivers only need
        # their numeric address, and resolving a local name can prompt on macOS.
        TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


def loopback_host(value, port):
    """True for a Host header naming a loopback address on the listener port."""
    try:
        parts = urlsplit("//" + (value or ""))
        host, given = parts.hostname, parts.port
    except ValueError:
        return False
    if given != port or not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
