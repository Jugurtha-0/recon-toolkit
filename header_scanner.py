#!/usr/bin/env python3
"""Audit des en-têtes de sécurité HTTP d'un site (équivalent pédagogique de securityheaders.com).
Requêtes GET passives uniquement : aucune charge utile envoyée, rien n'est exploité."""
import argparse
import json
import urllib.request
import ssl

# (en-tête, sévérité si absent, description)
SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HIGH", "Force HTTPS, protège contre le downgrade / sslstrip"),
    ("Content-Security-Policy", "HIGH", "Limite les sources de scripts, réduit le risque XSS"),
    ("X-Frame-Options", "MEDIUM", "Empêche le clickjacking (chargement en iframe)"),
    ("X-Content-Type-Options", "MEDIUM", "Empêche le MIME-sniffing (nosniff)"),
    ("Referrer-Policy", "LOW", "Limite les informations envoyées dans l'en-tête Referer"),
    ("Permissions-Policy", "LOW", "Restreint l'accès aux API navigateur (caméra, géoloc...)"),
]

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]


def fetch_headers(url, timeout=5, verify_tls=True):
    req = urllib.request.Request(url, headers={"User-Agent": "recon-toolkit/1.0"}, method="GET")
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return dict(resp.getheaders()), resp.status


def audit(url, timeout=5):
    headers, status = fetch_headers(url, timeout)
    findings = []
    for name, severity, desc in SECURITY_HEADERS:
        if name not in headers:
            findings.append({"header": name, "status": "MISSING", "severity": severity, "info": desc})
        else:
            findings.append({"header": name, "status": "PRESENT", "severity": severity, "info": headers[name][:80]})
    leaks = {h: headers[h] for h in LEAKY_HEADERS if h in headers}
    return {"url": url, "http_status": status, "findings": findings, "info_leaks": leaks}


def to_markdown(result):
    out = [f"# Audit des en-têtes — {result['url']}", "", f"Statut HTTP : {result['http_status']}", "",
           "| En-tête | État | Sévérité | Détail |", "|---|---|---|---|"]
    icon = {"MISSING": "❌", "PRESENT": "✅"}
    for f in result["findings"]:
        out.append(f"| {f['header']} | {icon[f['status']]} {f['status']} | {f['severity']} | {f['info']} |")
    if result["info_leaks"]:
        out += ["", "## Fuite d'information (bannières de version)"]
        out += [f"- `{k}`: {v}" for k, v in result["info_leaks"].items()]
    return "\n".join(out) + "\n"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("url")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.add_argument("--no-verify-tls", action="store_true")
    a = p.parse_args()
    if not a.url.startswith(("http://", "https://")):
        a.url = "https://" + a.url
    result = audit(a.url)
    print(json.dumps(result, indent=2) if a.format == "json" else to_markdown(result))


if __name__ == "__main__":
    main()
