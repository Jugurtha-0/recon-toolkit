#!/usr/bin/env python3
"""Scanner de ports TCP multithread avec banner grabbing.
À N'UTILISER QUE sur des systèmes dont vous êtes propriétaire ou pour lesquels
vous avez une autorisation écrite. Voir README.md."""
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 27017: "MongoDB",
}


def parse_ports(spec):
    """'22,80,443' ou '1-1024' -> liste d'entiers (dédupliquée, triée)."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def grab_banner(sock):
    try:
        sock.settimeout(1)
        data = sock.recv(256)
        return data.decode(errors="replace").strip().split("\n")[0][:80]
    except (socket.timeout, OSError):
        return ""


def scan_port(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner = grab_banner(s)
            return {"port": port, "state": "open", "service": COMMON_PORTS.get(port, "?"), "banner": banner}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan(host, ports, timeout=1.0, workers=100):
    """Scan TCP connect (pas de scan SYN brut : aucun privilège root requis)."""
    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, host, p, timeout): p for p in ports}
        for f in as_completed(futures):
            r = f.result()
            if r:
                results.append(r)
    return sorted(results, key=lambda r: r["port"])


def to_table(host, results):
    if not results:
        return f"Aucun port ouvert trouvé sur {host}.\n"
    out = [f"Résultats du scan — {host}", "", "PORT     SERVICE      BANNIÈRE", "-" * 50]
    for r in results:
        out.append(f"{r['port']:<8} {r['service']:<12} {r['banner']}")
    return "\n".join(out) + "\n"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("host")
    p.add_argument("--ports", default="1-1024", help="ex: '22,80,443' ou '1-1024' (défaut)")
    p.add_argument("--timeout", type=float, default=1.0)
    p.add_argument("--workers", type=int, default=100)
    p.add_argument("-y", "--yes", action="store_true", help="confirme l'autorisation de scanner cette cible")
    a = p.parse_args()

    if not a.yes:
        print("⚠️  Vous devez confirmer être autorisé à scanner cette cible avec --yes (voir README).")
        raise SystemExit(1)

    results = scan(a.host, parse_ports(a.ports), a.timeout, a.workers)
    print(to_table(a.host, results))


if __name__ == "__main__":
    main()
