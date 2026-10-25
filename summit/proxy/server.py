from __future__ import annotations

import socket
import sqlite3
import ssl
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ProxyServer:
    """Intercepting HTTP proxy with a SQLite site map.

    Behavior:
      - plain HTTP requests are forwarded and logged
      - HTTPS CONNECT tunnels are logged; with tls_intercept=True they are
        decrypted with a locally generated CA (see proxy/ca.py), every
        inner request is logged into the site map, and the origin is
        reached over its own TLS session (origin certificates are not
        verified - that is the point of a testing proxy)
      - without tls_intercept, CONNECT tunnels are relayed untouched

    Known limitation: request bodies are only read from the initial buffer,
    which covers typical proxy use (browsers send small bodies in one packet)
    but not multi-megabyte uploads.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        db_path: str = "summit_sitemap.db",
        tls_intercept: bool = False,
        ca_dir: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.db_path = db_path
        self.tls_intercept = tls_intercept
        self.ca_dir = Path(ca_dir).expanduser() if ca_dir else None
        self._server: socket.socket | None = None
        self._running = False
        self._db_lock = threading.Lock()
        self._forwarder = requests.Session()
        # Keep the response bytes plain so we can relay them untouched.
        self._forwarder.headers["Accept-Encoding"] = "identity"
        self._ca_ready = False
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sitemap ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "ts TEXT, method TEXT, url TEXT, status INTEGER, length INTEGER)"
        )
        conn.commit()
        conn.close()

    def _log(self, method: str, url: str, status: int, length: int) -> None:
        with self._db_lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "INSERT INTO sitemap (ts, method, url, status, length) VALUES (?, ?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), method, url, status, length),
            )
            conn.commit()
            conn.close()

    def start(self) -> None:
        if self.tls_intercept:
            from .ca import load_or_create_ca

            self._ca_dir = Path(self.ca_dir).expanduser() if self.ca_dir else Path.home() / ".summit" / "proxy-ca"
            load_or_create_ca(self._ca_dir)  # raises CaUnavailable without the optional package
            self._ca_ready = True
            print(f"[*] TLS interception on - CA certificate: {self._ca_dir / 'ca.crt'}")
            print("[*] trust this CA once in your browser or OS, then HTTPS through the proxy is logged in plaintext")
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(50)
        self._running = True
        print(f"[*] summit proxy listening on {self.host}:{self.port} (site map: {self.db_path})")
        while self._running:
            try:
                conn, _addr = self._server.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def stop(self) -> None:
        self._running = False
        if self._server is not None:
            self._server.close()

    def _handle(self, conn: socket.socket) -> None:
        try:
            head = self._read_head(conn)
            if not head:
                return
            request_line = head.split(b"\r\n", 1)[0].decode("latin-1")
            parts = request_line.split()
            if len(parts) < 2:
                return
            method, target = parts[0].upper(), parts[1]
            if method == "CONNECT":
                self._handle_connect(conn, target)
            else:
                self._handle_http(conn, method, target, head)
        finally:
            conn.close()

    @staticmethod
    def _read_head(conn: socket.socket, limit: int = 65536) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < limit:
            chunk = conn.recv(8192)
            if not chunk:
                break
            data += chunk
        return data

    def _handle_connect(self, conn: socket.socket, target: str) -> None:
        host, _, port_text = target.partition(":")
        port = int(port_text or 443)
        self._log("CONNECT", f"https://{target}", 0, 0)
        if self.tls_intercept:
            self._handle_connect_intercept(conn, host, port)
            return
        try:
            remote = socket.create_connection((host, port), timeout=10)
        except OSError:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        # Relay the encrypted stream untouched, both directions. When EITHER
        # side ends (the client walks away, or the origin closes after
        # Connection: close), both sockets shut down so the peer sees a real
        # EOF instead of waiting forever - joining one direction only used to
        # strand the client exactly there.
        client_to_remote = threading.Thread(target=self._pipe, args=(conn, remote), daemon=True)
        remote_to_client = threading.Thread(target=self._pipe, args=(remote, conn), daemon=True)
        client_to_remote.start()
        remote_to_client.start()
        while client_to_remote.is_alive() and remote_to_client.is_alive():
            time.sleep(0.05)
        for sock in (conn, remote):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        client_to_remote.join(timeout=1)
        remote_to_client.join(timeout=1)
        try:
            remote.close()
        except OSError:
            pass

    def _handle_connect_intercept(self, conn: socket.socket, host: str, port: int) -> None:
        """Decrypt the tunnel, log every inner request, re-encrypt upstream.

        The client gets a leaf certificate signed by the local proxy CA
        (trust it once, like Burp's); the origin gets its own TLS session
        with verification off, which is the nature of an intercepting proxy.
        """
        if not self._ca_ready:
            self._ca_dir = self._ca_dir or (Path.home() / ".summit" / "proxy-ca")
            self._ca_ready = True  # start() preloads the CA; direct users of the class get it on first tunnel
        try:
            from .ca import issue_leaf

            leaf = issue_leaf(self._ca_dir, host)
        except Exception as exc:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            self._log("CONNECT-ERROR", f"https://{host}:{port}", 0, 0)
            print(f"[proxy] could not issue a leaf certificate for {host}: {exc}")
            return

        try:
            remote = socket.create_connection((host, port), timeout=10)
        except OSError:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        client_ctx.load_cert_chain(str(leaf))
        origin_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        origin_ctx.check_hostname = False
        origin_ctx.verify_mode = ssl.CERT_NONE
        try:
            client_tls = client_ctx.wrap_socket(conn, server_side=True)
            remote_tls = origin_ctx.wrap_socket(remote, server_hostname=host)
        except (ssl.SSLError, OSError) as exc:
            print(f"[proxy] TLS handshake failed for {host}:{port}: {exc}")
            try:
                remote.close()
            except OSError:
                pass
            return

        try:
            # Sequential requests over the intercepted tunnel. A client that
            # signals Connection: close gets its response and an EOF, not a
            # tunnel that waits forever for a next request that never comes.
            while self._running:
                head = self._read_head(client_tls)
                if not head:
                    break
                request_line = head.split(b"\r\n", 1)[0].decode("latin-1")
                parts = request_line.split()
                if len(parts) < 2:
                    break
                method, path = parts[0].upper(), parts[1]
                target = f"https://{host}:{port}{path}" if path.startswith("/") else path
                if not self._relay_request(client_tls, method, target, head):
                    break
        finally:
            try:
                remote_tls.close()
            except OSError:
                pass
            try:
                client_tls.close()
            except OSError:
                pass

    def _relay_request(self, conn: socket.socket, method: str, target: str, head: bytes) -> bool:
        """Forward one plain-HTTP request and write the response back.

        Returns True when the connection may carry another request, False
        when the caller should stop (unreachable origin, request without a
        path, or a client that asked for Connection: close).
        """
        if not urlsplit(target).netloc:
            return False
        headers: dict[str, str] = {}
        body = b""
        close_after = False
        pieces = head.split(b"\r\n\r\n", 1)
        if len(pieces) == 2:
            for raw_line in pieces[0].split(b"\r\n")[1:]:
                decoded = raw_line.decode("latin-1")
                if ":" in decoded:
                    key, _, value = decoded.partition(":")
                    key, value = key.strip(), value.strip()
                    if key.lower() == "connection" and value.lower() == "close":
                        close_after = True
                    headers[key] = value
            body = pieces[1]
        for hop in ("proxy-connection", "keep-alive", "connection"):
            headers.pop(hop, None)
        try:
            response = self._forwarder.request(
                method,
                target,
                headers=headers,
                data=body if body else None,
                timeout=30,
                allow_redirects=False,
                verify=False,
            )
        except requests.RequestException:
            try:
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            return False
        self._write_response(conn, response, close_after=close_after)
        self._log(method, target, response.status_code, len(response.content))
        return not close_after

    @staticmethod
    def _write_response(conn: socket.socket, response: requests.Response, close_after: bool = False) -> None:
        """Write a requests response as a raw HTTP/1.1 reply.

        Transfer-Encoding is dropped and Content-Length set from the
        decoded body - relaying chunked framing alongside a decoded body
        would desync the client's connection framing.
        """
        status_line = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
        headers_out = ""
        for key, value in response.headers.items():
            if key.lower() in ("transfer-encoding", "content-length", "connection"):
                continue
            headers_out += f"{key}: {value}\r\n"
        headers_out += f"Content-Length: {len(response.content)}\r\n"
        if close_after:
            headers_out += "Connection: close\r\n"
        conn.sendall((status_line + headers_out + "\r\n").encode("latin-1", errors="replace") + response.content)

    @staticmethod
    def _pipe(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass

    def _handle_http(self, conn: socket.socket, method: str, target: str, head: bytes) -> None:
        if not urlsplit(target).netloc:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        self._relay_request(conn, method, target, head)
