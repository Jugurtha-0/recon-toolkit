#!/usr/bin/env python3
"""Point d'entrée unique : enchaîne scan de ports + audit des en-têtes HTTP si 80/443 ouverts."""
import argparse
from port_scanner import scan, parse_ports, to_table
from header_scanner import audit, to_markdown


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("host")
    p.add_argument("--ports", default="1-1024")
    p.add_argument("-y", "--yes", action="store_true")
    a = p.parse_args()
    if not a.yes:
        print("⚠️  Confirmez l'autorisation avec --yes (voir README : usage légal uniquement).")
        raise SystemExit(1)

    results = scan(a.host, parse_ports(a.ports))
    print(to_table(a.host, results))

    open_ports = {r["port"] for r in results}
    for port, scheme in ((443, "https"), (80, "http")):
        if port in open_ports:
            print(to_markdown(audit(f"{scheme}://{a.host}")))
            break


if __name__ == "__main__":
    main()
