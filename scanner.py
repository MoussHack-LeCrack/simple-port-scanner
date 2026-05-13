#!/usr/bin/env python3

import argparse
import json
import socket
import time


SERVICES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-alt",
}


def parse_ports(ports_text):
    """Transforme '22,80,443' ou '1-100' en liste de ports."""
    ports = []

    for part in ports_text.split(","):
        part = part.strip()

        if "-" in part:
            start, end = part.split("-", 1)
            start = int(start)
            end = int(end)
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))

    ports = sorted(set(ports))

    for port in ports:
        if port < 1 or port > 65535:
            raise ValueError("les ports doivent etre entre 1 et 65535")

    return ports


def parse_targets(targets_text):
    """Transforme 'site.com,127.0.0.1' en liste de cibles."""
    targets = []

    for target in targets_text.split(","):
        target = target.strip()
        if target:
            targets.append(target)

    if not targets:
        raise ValueError("aucune cible donnee")

    return targets


def detect_service(port, banner):
    """Essaie de deviner le service."""
    if banner:
        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            return "SSH"
        if "http" in banner_lower:
            return "HTTP"
        if "smtp" in banner_lower:
            return "SMTP"
        if "ftp" in banner_lower:
            return "FTP"

    return SERVICES.get(port, "inconnu")


def grab_banner(sock, port):
    """Lit une petite banniere si le service en donne une."""
    try:
        sock.settimeout(1)

        if port in (80, 8080):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

        data = sock.recv(1024)
        return data.decode(errors="ignore").strip()[:120]
    except OSError:
        return ""


def scan_port(target, port, timeout):
    """Teste un port TCP."""
    start_time = time.time()
    result = {
        "port": port,
        "state": "closed",
        "service": SERVICES.get(port, "inconnu"),
        "banner": "",
        "response_time": 0,
    }

    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if sock.connect_ex((target, port)) == 0:
            banner = grab_banner(sock, port)
            result["state"] = "open"
            result["banner"] = banner
            result["service"] = detect_service(port, banner)

    except OSError:
        pass
    finally:
        result["response_time"] = round(time.time() - start_time, 3)
        if sock:
            sock.close()

    return result


def print_result(result, verbose):
    """Affiche un resultat avec une petite mise en forme."""
    if result["state"] != "open" and not verbose:
        return

    print("-" * 45)
    print(f"Port        : {result['port']}/tcp")
    print(f"Etat        : {result['state']}")
    print(f"Service     : {result['service']}")
    print(f"Temps       : {result['response_time']}s")

    if result["banner"]:
        print(f"Banniere    : {result['banner']}")
    else:
        print("Banniere    : aucune")


def scan_target(target, ports, timeout, verbose, json_mode):
    """Scanne une cible complete."""
    results = []
    scan_start = time.time()

    try:
        ip_address = socket.gethostbyname(target)
    except OSError:
        ip_address = "resolution impossible"

    if not json_mode:
        print("=" * 55)
        print(f"Cible       : {target}")
        print(f"IP          : {ip_address}")
        print(f"Ports       : {len(ports)}")
        print(f"Timeout     : {timeout}s")
        print("=" * 55)

    if ip_address == "resolution impossible":
        if not json_mode:
            print("Erreur      : impossible de resoudre cette cible")
        return {
            "target": target,
            "ip": ip_address,
            "error": "resolution impossible",
            "results": [],
            "open_ports": 0,
            "closed_ports": 0,
            "scan_time": 0,
        }

    for port in ports:
        result = scan_port(target, port, timeout)
        results.append(result)

        if not json_mode:
            print_result(result, verbose)

    open_ports = len([result for result in results if result["state"] == "open"])
    closed_ports = len(results) - open_ports
    scan_time = round(time.time() - scan_start, 3)

    if not json_mode:
        print("-" * 45)
        print("Resume")
        print(f"Ports ouverts : {open_ports}")
        print(f"Ports fermes  : {closed_ports}")
        print(f"Duree scan    : {scan_time}s")
        print()

    visible_results = []
    for result in results:
        if result["state"] == "open" or verbose:
            visible_results.append(result)

    return {
        "target": target,
        "ip": ip_address,
        "results": visible_results,
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "scan_time": scan_time,
    }


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Petit scanner TCP pour apprendre. "
            "A utiliser seulement sur vos machines ou avec autorisation."
        )
    )
    parser.add_argument("--target", help="IP ou nom de domaine a scanner")
    parser.add_argument("--targets", help="plusieurs cibles separees par des virgules")
    parser.add_argument("--ports", required=True, help="exemple: 22,80,443 ou 1-1024")
    parser.add_argument("--timeout", type=float, default=1.0, help="timeout en secondes")
    parser.add_argument("--json", action="store_true", help="sortie au format JSON")
    parser.add_argument("--verbose", action="store_true", help="affiche aussi les ports fermes")
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as error:
        print(f"Erreur ports: {error}")
        return

    if args.targets:
        try:
            targets = parse_targets(args.targets)
        except ValueError as error:
            print(f"Erreur cibles: {error}")
            return
    elif args.target:
        targets = [args.target]
    else:
        print("Erreur: utilisez --target ou --targets")
        return

    if args.timeout <= 0:
        print("Erreur: le timeout doit etre plus grand que 0")
        return

    all_results = []

    for target in targets:
        result = scan_target(target, ports, args.timeout, args.verbose, args.json)
        all_results.append(result)

    if args.json:
        print(json.dumps({
            "targets": all_results,
        }, indent=2))


if __name__ == "__main__":
    main()
