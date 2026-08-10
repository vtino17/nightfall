import ipaddress
import re
import socket


class ScanTarget:
    def __init__(self, host, port=None, protocol="tcp"):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.service = None
        self.status = "unknown"
        self.banner = None
        self.vulnerabilities = []

    def __repr__(self):
        if self.port:
            return f"ScanTarget({self.host}:{self.port}/{self.protocol})"
        return f"ScanTarget({self.host})"

    def __eq__(self, other):
        if not isinstance(other, ScanTarget):
            return NotImplemented
        return (self.host == other.host and self.port == other.port
                and self.protocol == other.protocol)

    def __hash__(self):
        return hash((self.host, self.port, self.protocol))


class TargetParser:
    def __init__(self):
        self.host_re = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$')

    def parse(self, target_str, ports_str=None):
        ports = self._parse_ports(ports_str) if ports_str else [None]
        targets = target_str.replace(",", " ").split()
        result = []
        for raw in targets:
            raw = raw.strip()
            if not raw:
                continue
            expanded = self._expand(raw)
            for host in expanded:
                for port in ports:
                    result.append(ScanTarget(host, port=port) if port else ScanTarget(host))
        return result

    def _parse_ports(self, ports_str):
        ports = []
        for part in ports_str.replace(",", " ").split():
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                lo, hi = part.split("-", 1)
                ports.extend(range(int(lo), int(hi) + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))

    def _expand(self, raw):
        if self._is_cidr(raw):
            return [str(ip) for ip in ipaddress.ip_network(raw, strict=False).hosts()]
        if self._is_ip(raw):
            return [raw]
        if self._is_hostname(raw):
            return [raw]
        raise ValueError(f"Unrecognized target format: {raw}")

    def _is_ip(self, raw):
        try:
            ipaddress.ip_address(raw)
            return True
        except ValueError:
            return False

    def _is_cidr(self, raw):
        try:
            ipaddress.ip_network(raw, strict=False)
            return "/" in raw
        except ValueError:
            return False

    def _is_hostname(self, raw):
        return bool(self.host_re.match(raw)) or raw.startswith("_")
