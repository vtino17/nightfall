import json
import urllib.request
import urllib.error


class SlackNotifier:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    def send(self, message, severity=None):
        payload = self._build_payload(message, severity)
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            return False

    def send_scan_summary(self, findings, scan_name=None):
        total = len(findings)
        vuln_count = sum(len(f.get("vulnerabilities", [])) for f in findings)
        critical = sum(1 for f in findings for v in f.get("vulnerabilities", []) if v.get("severity") == "critical")
        header = f"*Nightfall Scan{' - ' + scan_name if scan_name else ''}*"
        message = (
            f"{header}\n"
            f"Targets: {total}\n"
            f"Vulnerabilities: {vuln_count}\n"
            f"Critical: {critical}"
        )
        return self.send(message)

    def _build_payload(self, message, severity=None):
        color_map = {"critical": "danger", "high": "warning", "medium": "warning", "low": "good"}
        color = color_map.get(severity, None)
        if color:
            return {
                "attachments": [{"color": color, "text": message, "mrkdwn_in": ["text"]}]
            }
        return {"text": message}


class SlackNotifierBuilder:
    @staticmethod
    def from_config(config):
        url = config.get("slack_webhook") or config.get("slack", {}).get("webhook_url")
        if not url:
            raise ValueError("Slack webhook URL required")
        return SlackNotifier(url)
