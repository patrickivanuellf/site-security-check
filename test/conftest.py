"""Local test servers: plain HTTP and HTTPS with a throw-away self-signed cert."""
import http.server
import itertools
import shutil
import socket
import ssl
import subprocess
import threading

import pytest

HTML_404 = (404, [("Content-Type", "text/html")], b"<html>not found</html>")
_counter = itertools.count()


def make_handler(routes):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self):
            path = self.path.split("?")[0]
            status, headers, body = routes.get(path) or routes.get("*") or HTML_404
            self.send_response_only(status)  # no default Server/Date headers
            for key, value in headers:
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    return Handler


class Server:
    def __init__(self, routes, cert=None):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(routes))
        if cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*cert)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.cert_path = cert[0] if cert else None
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def make_cert(directory, days):
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available")
    n = next(_counter)
    key, crt = directory / f"key{n}.pem", directory / f"crt{n}.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(crt), "-days", str(days), "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
        check=True, capture_output=True)
    return str(crt), str(key)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def start_server(tmp_path):
    """start_server(routes, tls_days=None) -> Server"""
    started = []

    def start(routes, tls_days=None):
        cert = make_cert(tmp_path, tls_days) if tls_days is not None else None
        server = Server(routes, cert)
        started.append(server)
        return server

    yield start
    for server in started:
        server.close()
