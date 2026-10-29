import sys, pathlib, socket, threading
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from port_scanner import parse_ports, scan


def test_parse_ports_mixed():
    assert parse_ports("22,80,1000-1002") == [22, 80, 1000, 1001, 1002]


def test_parse_ports_dedup_sorted():
    assert parse_ports("443,80,80") == [80, 443]


def test_scan_finds_local_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    threading.Thread(target=lambda: (srv.accept(), srv.close()), daemon=True).start()

    results = scan("127.0.0.1", [port], timeout=1)
    assert any(r["port"] == port and r["state"] == "open" for r in results)


def test_scan_skips_closed_port():
    # port très probablement fermé en local
    results = scan("127.0.0.1", [65123], timeout=0.3)
    assert results == []
