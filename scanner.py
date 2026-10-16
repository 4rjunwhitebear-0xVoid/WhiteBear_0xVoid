
#!/usr/bin/env python3

import socket
import ipaddress
import concurrent.futures
from datetime import datetime
from pathlib import Path

BANNER = r"""
 __        __ _     _       ____                 _
 \ \      / /| |__ (_) ___ | __ )  ___  __ _ _ __
  \ \ /\ / / | '_ \| |/ _ \|  _ \ / _ \/ _` | '__|
   \ V  V /  | |_) | | (_) | |_) |  __/ (_| | |
    \_/\_/   |_.__/|_|\___/|____/ \___|\__,_|_|

       WHITEBEAR NETWORK SCANNER v2.0
"""

COMMON_PORTS = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8000: "HTTP-alt",
    8080: "HTTP-proxy/alt",
    8443: "HTTPS-alt",
}

TIMEOUT = 0.35
MAX_WORKERS = 64


def service_name(port):
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]

    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "Unknown"


def scan_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            if sock.connect_ex((str(host), port)) == 0:
                return port, service_name(port)
    except OSError:
        pass

    return None


def scan_host(host, ports):
    results = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as pool:
        futures = [
            pool.submit(scan_port, str(host), port)
            for port in ports
        ]

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    return sorted(results)


def main():
    print(BANNER)
    print("Authorized private-network auditing only.\n")

    cidr = input(
        "Your authorized LAN subnet (example 192.168.1.0/24): "
    ).strip()

    try:
        network = ipaddress.ip_network(cidr, strict=False)

        if not network.is_private or network.version != 4:
            print("Error: enter an IPv4 private LAN subnet.")
            return

        if network.num_addresses > 256:
            print("Error: subnet is too large. Use /24 or smaller.")
            return

    except ValueError:
        print("Invalid network. Example: 192.168.1.0/24")
        return

    print("\n1. Common ports (recommended)")
    print("2. Ports 1-1024 (slower)")
    choice = input("Choose [1]: ").strip() or "1"

    if choice == "1":
        ports = sorted(COMMON_PORTS)
    elif choice == "2":
        ports = list(range(1, 1025))
    else:
        print("Invalid choice.")
        return

    hosts = [
        ip for ip in network.hosts()
        if ip != ipaddress.ip_address("127.0.0.1")
    ]

    reports_dir = Path.home() / "WhiteBear-Suite" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    report = [
        "WHITEBEAR NETWORK SCAN REPORT",
        f"Date: {datetime.now().isoformat(timespec='seconds')}",
        f"Network: {network}",
        f"Ports checked per host: {len(ports)}",
        "=" * 55,
    ]

    print(f"\nNetwork: {network}")
    print(f"Hosts to check: {len(hosts)}")
    print(f"TCP ports per host: {len(ports)}")
    print("Scanning authorized LAN; please wait...\n")

    found_hosts = 0

    try:
        for index, host in enumerate(hosts, start=1):
            open_ports = scan_host(host, ports)

            if open_ports:
                found_hosts += 1
                print(f"[HOST] {host}")
                report.append(f"\nHost: {host}")

                for port, service in open_ports:
                    line = f"  OPEN  TCP/{port:<5} Service: {service}"
                    print(line)
                    report.append(line)

            if index % 25 == 0:
                print(f"Progress: {index}/{len(hosts)} hosts")

    except KeyboardInterrupt:
        print("\nScan interrupted; saving partial report.")

    report.append(f"\nHosts with open ports: {found_hosts}")

    filename = (
        "whitebear_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".txt"
    )
    report_path = reports_dir / filename
    report_path.write_text("\n".join(report) + "\n", encoding="utf-8")

    print("\nScan finished.")
    print(f"Hosts with open ports: {found_hosts}")
    print(f"Report saved to: {report_path}")


if __name__ == "__main__":
    main()
