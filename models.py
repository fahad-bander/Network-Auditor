from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    severity: str
    title: str
    evidence: str
    remediation: str


@dataclass
class Service:
    port: int
    protocol: str
    name: str
    banner: Optional[str] = None


@dataclass
class HostReport:
    ip: str
    mac: Optional[str]
    hostname: Optional[str]
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
