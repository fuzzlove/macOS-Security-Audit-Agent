#!/usr/bin/env python3
"""Harmless loopback-only HTTP Basic fixture for MSAA scanner validation.

This is deliberately not a production service.  It binds only to 127.0.0.1
and accepts the documented test credential admin/admin so the defensive
scanner can be exercised without targeting a third-party system.
"""

from __future__ import annotations

import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIXTURE_USERNAME = "admin"
FIXTURE_PASSWORD = "admin"
FIXTURE_MARKER = b"MSAA DEFAULT CREDENTIAL FIXTURE"


class DefaultCredentialFixtureHandler(BaseHTTPRequestHandler):
    server_version = "MSAAFixture/1.0"

    def do_GET(self) -> None:
        expected = "Basic " + base64.b64encode(
            f"{FIXTURE_USERNAME}:{FIXTURE_PASSWORD}".encode()
        ).decode("ascii")
        if self.headers.get("Authorization", "") != expected:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="MSAA Fixture"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(FIXTURE_MARKER)))
        self.end_headers()
        self.wfile.write(FIXTURE_MARKER)

    def log_message(self, format: str, *args: object) -> None:
        print(f"fixture: {format % args}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the loopback-only MSAA default credential test fixture.")
    parser.add_argument("--port", type=int, default=18080, help="Loopback TCP port (default: 18080)")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), DefaultCredentialFixtureHandler)
    print(f"MSAA harmless fixture listening on http://127.0.0.1:{server.server_port}/")
    print("Test credential: admin / admin. Press Control-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
