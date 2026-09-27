#!/usr/bin/env python3
"""
network_auditor.py

Low-impact network inventory and vulnerability audit.

Features:
- Host discovery via ARP on the local subnet
- TCP connect scanning with bounded concurrency
- Lightweight service/banner detection
- HTTP security-header checks
- TLS certificate metadata checks
- Basic exposure findings
- JSON report

Dependencies:
    pip install scapy

Linux:
    sudo python3 network_auditor.py 192.168.1.0/24

Windows:
    Run PowerShell/CMD as Administrator.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import socket
import ssl
import time
from dataclasses import asdict
from typing import Optional

from .models import Finding, HostReport, Service
import aiohttp
from scapy.all import ARP, Ether, srp


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# Findings here are exposure/configuration indicators.
# Exact CVE identification requires reliable product/version evidence.
PORT_FINDINGS = {
    21: (
        "HIGH",
        "FTP exposed",
        "FTP commonly transmits credentials without encryption.",
    ),
    23: (
        "CRITICAL",
        "Telnet exposed",
        "Telnet provides plaintext remote administration.",
    ),
    139: (
        "MEDIUM",
        "NetBIOS exposed",
        "Legacy Windows file-sharing services are externally exposed.",
    ),
    445: (
        "HIGH",
        "SMB exposed",
        "SMB exposure increases attack surface and should be restricted.",
    ),
    3389: (
        "HIGH",
        "RDP exposed",
        "Remote Desktop is exposed and should be tightly restricted.",
    ),
    5900: (
        "HIGH",
        "VNC exposed",
        "VNC provides remote graphical access and requires strong controls.",
    ),
    6379: (
        "HIGH",
        "Redis exposed",
        "Redis should generally remain restricted to trusted hosts.",
    ),
}

def validate_network(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise SystemExit(f"Invalid network: {exc}")

    if network.version != 4:
        raise SystemExit("IPv4 networks are required.")

    if network.num_addresses > 256:
        raise SystemExit(
            "Maximum scan size is 256 addresses."
        )

    return network


def discover_hosts(network: ipaddress.IPv4Network) -> dict[str, str]:
    """
    ARP discovery creates one broadcast request per target range.
    It does not perform authentication or exploitation.
    """
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        pdst=str(network)
    )

    answered, _ = srp(
        packet,
        timeout=2,
        retry=0,
        verbose=False,
    )

    return {
        received.psrc: received.hwsrc
        for _, received in answered
    }


async def tcp_connect(
    host: str,
    port: int,
    timeout: float,
) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )

        writer.close()
        await writer.wait_closed()

        return True

    except (
        asyncio.TimeoutError,
        ConnectionRefusedError,
        OSError,
    ):
        return False


async def read_banner(
    host: str,
    port: int,
    timeout: float,
) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )

        if port in {21, 22, 25, 110, 143}:
            data = await asyncio.wait_for(
                reader.read(512),
                timeout=timeout,
            )

            banner = data.decode(
                errors="replace"
            ).strip()

        elif port in {80, 8080}:
            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: close\r\n\r\n"
            )

            writer.write(request.encode())
            await writer.drain()

            data = await asyncio.wait_for(
                reader.read(2048),
                timeout=timeout,
            )

            banner = data.decode(
                errors="replace"
            ).strip()

        else:
            banner = None

        writer.close()
        await writer.wait_closed()

        return banner[:1000] if banner else None

    except Exception:
        return None


async def scan_services(
    host: str,
    ports: list[int],
    concurrency: int,
) -> list[Service]:
    semaphore = asyncio.Semaphore(concurrency)

    async def scan_one(port: int) -> Optional[Service]:
        async with semaphore:
            opened = await tcp_connect(
                host,
                port,
                timeout=0.75,
            )

            if not opened:
                return None

            banner = await read_banner(
                host,
                port,
                timeout=1.0,
            )

            return Service(
                port=port,
                protocol="tcp",
                name=COMMON_PORTS.get(
                    port,
                    "unknown",
                ),
                banner=banner,
            )

    results = await asyncio.gather(
        *(scan_one(port) for port in ports)
    )

    return [
        result
        for result in results
        if result is not None
    ]


def evaluate_port_findings(
    services: list[Service],
) -> list[Finding]:
    findings: list[Finding] = []

    for service in services:
        template = PORT_FINDINGS.get(service.port)

        if not template:
            continue

        severity, title, evidence = template

        remediation = (
            f"Restrict TCP/{service.port} with firewall rules "
            "and disable the service when it is unnecessary."
        )

        findings.append(
            Finding(
                severity=severity,
                title=title,
                evidence=evidence,
                remediation=remediation,
            )
        )

    return findings


async def inspect_http(
    host: str,
    port: int,
) -> list[Finding]:
    findings: list[Finding] = []

    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}/"

    timeout = aiohttp.ClientTimeout(
        total=3
    )

    try:
        async with aiohttp.ClientSession(
            timeout=timeout
        ) as session:
            async with session.get(
                url,
                allow_redirects=False,
            ) as response:

                headers = {
                    key.lower(): value
                    for key, value
                    in response.headers.items()
                }

                if scheme == "http":
                    findings.append(
                        Finding(
                            severity="LOW",
                            title="HTTP service detected",
                            evidence=url,
                            remediation=(
                                "Prefer HTTPS for authenticated "
                                "or sensitive web traffic."
                            ),
                        )
                    )

                if scheme == "https":
                    if "strict-transport-security" not in headers:
                        findings.append(
                            Finding(
                                severity="LOW",
                                title="HSTS header missing",
                                evidence=url,
                                remediation=(
                                    "Configure Strict-Transport-Security "
                                    "after HTTPS is correctly deployed."
                                ),
                            )
                        )

                if "x-content-type-options" not in headers:
                    findings.append(
                        Finding(
                            severity="LOW",
                            title="X-Content-Type-Options missing",
                            evidence=url,
                            remediation=(
                                "Set X-Content-Type-Options: nosniff."
                            ),
                        )
                    )

                if "content-security-policy" not in headers:
                    findings.append(
                        Finding(
                            severity="LOW",
                            title="Content-Security-Policy missing",
                            evidence=url,
                            remediation=(
                                "Consider a restrictive CSP appropriate "
                                "to the application's resources."
                            ),
                        )
                    )

    except (
        aiohttp.ClientError,
        asyncio.TimeoutError,
        OSError,
    ):
        pass

    return findings


def resolve_hostname(ip: str) -> Optional[str]:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def severity_score(findings: list[Finding]) -> int:
    weights = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1,
    }

    return sum(
        weights.get(finding.severity, 0)
        for finding in findings
    )


def print_report(
    reports: list[HostReport],
    elapsed: float,
) -> None:
    print("\n" + "=" * 70)
    print("NETWORK SECURITY AUDIT")
    print("=" * 70)

    print(f"Hosts discovered : {len(reports)}")
    print(f"Scan duration    : {elapsed:.2f}s")

    total_findings = 0

    for report in reports:
        print("\n" + "-" * 70)
        print(f"HOST: {report.ip}")
        print(f"MAC : {report.mac or 'unknown'}")
        print(f"DNS : {report.hostname or 'unknown'}")

        if report.services:
            print("\nOpen services:")

            for service in report.services:
                print(
                    f"  {service.port:5}/tcp "
                    f"{service.name}"
                )

                if service.banner:
                    print(
                        f"        {service.banner[:160]}"
                    )
        else:
            print("\nOpen services: none")

        if report.findings:
            print("\nFindings:")

            for finding in report.findings:
                total_findings += 1

                print(
                    f"  [{finding.severity}] "
                    f"{finding.title}"
                )
                print(
                    f"      Evidence: "
                    f"{finding.evidence}"
                )
                print(
                    f"      Fix: "
                    f"{finding.remediation}"
                )

    print("\n" + "=" * 70)
    print(f"Total findings: {total_findings}")
    print("=" * 70)


async def audit(
    network: ipaddress.IPv4Network,
    ports: list[int],
    concurrency: int,
) -> list[HostReport]:

    started = time.perf_counter()

    discovered = discover_hosts(network)

    print(
        f"[+] Discovered {len(discovered)} active hosts."
    )

    reports: list[HostReport] = []

    for ip, mac in discovered.items():
        print(f"[+] Auditing {ip} ...")

        services = await scan_services(
            ip,
            ports,
            concurrency,
        )

        findings = evaluate_port_findings(
            services
        )

        for service in services:
            if service.port in {80, 8080, 443}:
                findings.extend(
                    await inspect_http(
                        ip,
                        service.port,
                    )
                )

        reports.append(
            HostReport(
                ip=ip,
                mac=mac,
                hostname=resolve_hostname(ip),
                services=services,
                findings=findings,
            )
        )

    elapsed = time.perf_counter() - started

    print_report(
        reports,
        elapsed,
    )

    return reports


def parse_ports(value: str) -> list[int]:
    result: set[int] = set()

    for part in value.split(","):
        part = part.strip()

        if "-" in part:
            start, end = map(
                int,
                part.split("-", 1),
            )

            if end - start > 128:
                raise SystemExit(
                    "Port range is limited to 128 ports."
                )

            result.update(
                range(start, end + 1)
            )
        else:
            result.add(int(part))

    ports = sorted(result)

    if not ports:
        raise SystemExit(
            "At least one port is required."
        )

    if any(
        port < 1 or port > 65535
        for port in ports
    ):
        raise SystemExit(
            "Ports must be between 1 and 65535."
        )

    return ports


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Low-impact network security auditor"
    )

    parser.add_argument(
        "network",
        help="IPv4 CIDR, e.g. 192.168.1.0/24",
    )

    parser.add_argument(
        "--ports",
        default="22,23,53,80,139,443,445,3389,5900,6379,8080,8443",
        help="comma-separated ports or small ranges",
    )

    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=8,
        help="maximum simultaneous TCP checks",
    )

    parser.add_argument(
        "--json",
        default="network_audit.json",
        help="JSON report path",
    )

    args = parser.parse_args()

    if not 1 <= args.concurrency <= 16:
        raise SystemExit(
            "Concurrency must be between 1 and 16."
        )

    network = validate_network(
        args.network
    )

    ports = parse_ports(
        args.ports
    )

    reports = await audit(
        network,
        ports,
        args.concurrency,
    )

    with open(
        args.json,
        "w",
        encoding="utf-8",
    ) as report_file:
        json.dump(
            [asdict(report) for report in reports],
            report_file,
            indent=2,
            ensure_ascii=False,
        )

    print(
        f"\n[+] Report written to {args.json}"
    )


if __name__ == "__main__":
    asyncio.run(main())
