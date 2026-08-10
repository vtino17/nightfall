import re
import json
from datetime import datetime, timezone


SEVERITY_LEVELS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

VULN_PATTERNS = [
    {"id": "SSL-001", "name": "Weak TLS Version",
     "pattern": re.compile(r"TLSv1\.0|TLSv1\.1|SSLv3", re.I),
     "severity": "high"},
    {"id": "BAN-001", "name": "Default Banner Disclosure",
     "pattern": re.compile(r"(Apache/2\.2\.\d+|nginx/1\.[0-9]\.|PHP/5\.)", re.I),
     "severity": "medium"},
    {"id": "BAN-002", "name": "Outdated Server Software",
     "pattern": re.compile(r"(Apache/1\.|IIS/6|IIS/7\.0)", re.I),
     "severity": "high"},
    {"id": "PORT-001", "name": "Non-Standard Port Open",
     "pattern": None,
     "severity": "low"},
    {"id": "PORT-002", "name": "Sensitive Service Exposed",
     "pattern": re.compile(r"^(telnet|ftp|rdp|vnc)$", re.I),
     "severity": "medium"},
]


class Scanner:
    def __init__(self):
        self.findings = []

    def analyze(self, results, cve_lookup=False, severity="medium"):
        min_level = SEVERITY_LEVELS.get(severity, 2)
        analyzed = []
        for target in results:
            result = self._scan_target(target)
            if cve_lookup and result.get("service") and result.get("banner"):
                result = self.enrich_cve(result)
            vulns = result.get("vulnerabilities", [])
            filtered = [v for v in vulns
                        if SEVERITY_LEVELS.get(v.get("severity", "info"), 0) >= min_level]
            result["vulnerabilities"] = filtered
            result["filtered_severity"] = severity
            analyzed.append(result)
        self.findings = analyzed
        return analyzed

    def _scan_target(self, target):
        result = {
            "host": target.host,
            "port": target.port,
            "protocol": target.protocol,
            "service": target.service,
            "status": target.status,
            "banner": getattr(target, "banner", None),
            "vulnerabilities": [],
            "scan_time": datetime.now(timezone.utc).isoformat(),
        }
        for rule in VULN_PATTERNS:
            if rule["id"] == "PORT-002":
                if result.get("service") and rule["pattern"].match(result["service"]):
                    result["vulnerabilities"].append({
                        "id": "PORT-002",
                        "name": "Sensitive Service Exposed",
                        "severity": "medium",
                        "source": "heuristic"
                    })
            elif rule["pattern"] and result.get("banner"):
                if rule["pattern"].search(result["banner"]):
                    result["vulnerabilities"].append({
                        "id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "source": "signature"
                    })
            elif rule["pattern"] is None and rule["id"] == "PORT-001":
                if result.get("port") and result["port"] not in range(1, 1024):
                    result["vulnerabilities"].append({
                        "id": "PORT-001",
                        "name": "Non-Standard Port Open",
                        "severity": "low",
                        "source": "heuristic"
                    })
        return result

    def enrich_cve(self, result):
        if not result.get("service") or not result.get("banner"):
            return result
        service = result["service"].lower()
        version = self._extract_version(result["banner"])
        if not version:
            return result
        cves = self._mock_cve_lookup(service, version)
        if cves:
            result["vulnerabilities"].extend(cves)
        return result

    def _extract_version(self, banner):
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", banner)
        return m.group(1) if m else None

    def _mock_cve_lookup(self, service, version):
        known = {
            "ssh": {
                "7.2": [{"id": "CVE-2016-6210", "name": "SSH User Enumeration", "severity": "medium"}],
                "7.4": [{"id": "CVE-2017-15906", "name": "SSH DoS via MaxStartups", "severity": "medium"}],
            },
            "http": {
                "2.4.49": [{"id": "CVE-2021-41773", "name": "Apache Path Traversal", "severity": "critical"}],
                "2.4.50": [{"id": "CVE-2021-42013", "name": "Apache Path Traversal Bypass", "severity": "critical"}],
            },
            "vsftpd": {
                "2.3.4": [{"id": "CVE-2011-2523", "name": "vsftpd Backdoor", "severity": "critical"}],
            },
        }
        return known.get(service, {}).get(version, [])
