import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from header_scanner import audit, SECURITY_HEADERS
import http.server
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Strict-Transport-Security", "max-age=63072000")
        self.send_header("Server", "nginx/1.18.0")
        self.end_headers()

    def log_message(self, *a):
        pass


def start_server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_audit_detects_present_and_missing_headers():
    srv = start_server()
    try:
        result = audit(f"http://127.0.0.1:{srv.server_port}")
        by_name = {f["header"]: f["status"] for f in result["findings"]}
        assert by_name["Strict-Transport-Security"] == "PRESENT"
        assert by_name["Content-Security-Policy"] == "MISSING"
        assert result["info_leaks"]["Server"] == "nginx/1.18.0"
    finally:
        srv.shutdown()


def test_all_headers_checked():
    names = {h for h, _, _ in SECURITY_HEADERS}
    assert "Content-Security-Policy" in names and "X-Frame-Options" in names
