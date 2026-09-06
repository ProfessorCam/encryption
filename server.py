#!/usr/bin/env python3
"""HTTPS teaching server.

Serves a Tux login page over TLS 1.2 with RSA key exchange (no forward
secrecy) so students can decrypt their own captured traffic in Wireshark
using either the server's RSA private key or the exported session secrets.
"""

import html
import ssl
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CERT_DIR = Path("/certs")
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE = CERT_DIR / "server.key"
KEYLOG_FILE = CERT_DIR / "keylog.txt"
TEMPLATE_FILE = Path("/app/index.html")

# RSA key-exchange ciphers only (no ECDHE) so the private key alone can
# decrypt a capture. Pinning to TLS 1.2 keeps these suites reachable.
RSA_CIPHERS = "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"


def read_public_key() -> str:
    """Extract the certificate's public key in PEM form."""
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", str(CERT_FILE), "-noout", "-pubkey"],
            capture_output=True, text=True, check=True,
        )
        return out.stdout.strip()
    except Exception as exc:  # pragma: no cover - defensive
        return f"(could not read public key: {exc})"


def read_file(path: Path, empty_msg: str) -> str:
    try:
        text = path.read_text().strip()
        return text if text else empty_msg
    except FileNotFoundError:
        return empty_msg


class Handler(BaseHTTPRequestHandler):
    server_version = "HTTPSDemo/1.0"

    def _send(self, body: bytes, content_type: str, status: int = 200,
              download_name: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if download_name:
            self.send_header(
                "Content-Disposition", f'attachment; filename="{download_name}"'
            )
        self.end_headers()
        self.wfile.write(body)

    def _serve_page(self) -> None:
        template = TEMPLATE_FILE.read_text()
        public_key = read_public_key()
        private_key = read_file(KEY_FILE, "(private key not found)")
        keylog = read_file(
            KEYLOG_FILE,
            "(empty — submit the form, then refresh this page to see your "
            "session's symmetric secret)",
        )
        page = (
            template
            .replace("{PUBLIC_KEY}", html.escape(public_key))
            .replace("{PRIVATE_KEY}", html.escape(private_key))
            .replace("{KEYLOG}", html.escape(keylog))
        )
        self._send(page.encode(), "text/html; charset=utf-8")

    def _serve_confirmation(self) -> None:
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        note = ""
        if query:
            note = (
                "<p class=\"ok\">Your submission just travelled across the network as the "
                f"encrypted request <code>GET {html.escape(self.path)}</code>. "
                "Nobody sniffing the wire can read it, unless they have "
                "the keys. You do.</p>"
            )
        body = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sent over HTTPS</title>
<style>
:root{{--ink:#1b2233;--muted:#5b6577;--line:#dde3ec;--bg:#f4f6fa;--panel:#fff;--accent:#2f6fed;--sym:#d9762b}}
body{{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,sans-serif;color:var(--ink);background:var(--bg);margin:0;padding:48px 20px;line-height:1.55}}
.card{{max-width:680px;margin:0 auto;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:26px 30px}}
h1{{font-size:26px;margin:0 0 10px}} p{{margin:0 0 12px}} .ok{{color:#14532d;background:#e6f7ec;border:1px solid #9ad4ae;border-radius:10px;padding:10px 14px;margin-bottom:14px}}
code{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.92em;background:#eef1f6;padding:1px 5px;border-radius:4px;word-break:break-all}}
.dl{{display:inline-block;background:var(--accent);color:#fff;text-decoration:none;font-weight:600;font-size:14px;padding:8px 14px;border-radius:8px;margin:4px 8px 4px 0}}
.dl.sym{{background:var(--sym)}} a{{color:var(--accent)}} ul{{padding-left:20px}} li{{margin-bottom:8px}}
</style></head>
<body><div class="card">
<h1>&#128274; Sent over HTTPS, encrypted end to end.</h1>
{note}
<p><b>Now go find your password in Wireshark.</b> Your capture holds this request, but it is ciphertext until you load the keys. Grab them here:</p>
<ul>
  <li><a class="dl sym" href="/keylog.txt">keylog.txt</a> session secrets, the reliable method (Wireshark: TLS &rarr; (Pre)-Master-Secret log filename)</li>
  <li><a class="dl" href="/server.key">server.key</a> RSA private key, advanced and build-dependent (Wireshark: TLS &rarr; RSA keys list)</li>
</ul>
<p><a href="/">&larr; Back to the login page</a></p>
</div></body>
</html>"""
        self._send(body.encode(), "text/html; charset=utf-8")

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._serve_page()
        elif path == "/action_page.php":
            self._serve_confirmation()
        elif path == "/server.key":
            self._send(KEY_FILE.read_bytes(), "text/plain",
                       download_name="server.key")
        elif path == "/server.crt":
            self._send(CERT_FILE.read_bytes(), "text/plain",
                       download_name="server.crt")
        elif path == "/keylog.txt":
            data = KEYLOG_FILE.read_bytes() if KEYLOG_FILE.exists() else b""
            self._send(data, "text/plain", download_name="keylog.txt")
        else:
            self._send(b"Not found", "text/plain", status=404)

    def log_message(self, fmt: str, *args) -> None:
        print("[https-demo] " + (fmt % args))


def main() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(RSA_CIPHERS)
    # Export symmetric session secrets so students can decrypt their captures.
    ctx.keylog_filename = str(KEYLOG_FILE)

    httpd = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("[https-demo] Serving HTTPS on 0.0.0.0:443 (TLS 1.2, RSA ciphers)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
