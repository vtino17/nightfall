import json
from datetime import datetime

from nightfall.reporters.base import BaseReporter


class JSONReporter(BaseReporter):
    def format_name(self):
        return "json"

    def generate(self, findings, metadata=None):
        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "metadata": metadata or {},
            "summary": self._summarize(findings),
            "findings": findings,
        }
        return json.dumps(report, indent=2, default=str)

    def _summarize(self, findings):
        total = len(findings)
        open_ports = sum(1 for f in findings if f.get("status") == "open")
        closed = sum(1 for f in findings if f.get("status") == "closed")
        vuln_count = sum(len(f.get("vulnerabilities", [])) for f in findings)
        return {
            "total_targets": total,
            "open_ports": open_ports,
            "closed_ports": closed,
            "total_vulnerabilities": vuln_count,
            "severity_breakdown": self._severity_breakdown(findings),
        }

    def _severity_breakdown(self, findings):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            for v in f.get("vulnerabilities", []):
                sev = v.get("severity", "info")
                if sev in counts:
                    counts[sev] += 1
        return counts
