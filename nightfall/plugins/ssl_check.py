import ssl
import socket
from datetime import datetime

from nightfall.core.plugin import BasePlugin


class SSLCheck(BasePlugin):
    name = "ssl_check"
    version = "1.0"
    description = "Checks SSL/TLS certificate validity and cipher strength"

    def __init__(self):
        super().__init__()
        self.weak_ciphers = {"RC4", "DES", "3DES", "EXPORT", "NULL", "MD5"}

    def should_run(self, target):
        if target.port in (443, 8443, 993, 995, 465, 636):
            return True
        if target.service in ("https", "imaps", "pop3s", "smtps", "ldaps"):
            return True
        return False

    def run(self, target):
        result = {
            "host": target.host,
            "port": target.port,
            "certificate": None,
            "expiry": None,
            "days_remaining": None,
            "cipher": None,
            "tls_version": None,
            "issues": [],
            "valid": False,
        }
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((target.host, target.port), timeout=10)
            ssock = ctx.wrap_socket(sock, server_hostname=target.host)
            cert = ssock.getpeercert()
            result["certificate"] = {
                "subject": dict(cert.get("subject", [])),
                "issuer": dict(cert.get("issuer", [])),
                "serial": cert.get("serialNumber"),
                "subjectAltName": cert.get("subjectAltName", []),
            }
            not_after = cert.get("notAfter", "")
            result["expiry"] = not_after
            try:
                expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                remaining = (expiry_dt - datetime.utcnow()).days
                result["days_remaining"] = remaining
                if remaining < 0:
                    result["issues"].append("Certificate expired")
                elif remaining < 30:
                    result["issues"].append(f"Certificate expires in {remaining} days")
            except ValueError:
                pass
            cipher = ssock.cipher()
            if cipher:
                result["cipher"] = cipher[0]
                result["tls_version"] = cipher[1]
                for weak in self.weak_ciphers:
                    if weak in cipher[0]:
                        result["issues"].append(f"Weak cipher: {cipher[0]}")
            result["valid"] = len(result["issues"]) == 0
            ssock.close()
            sock.close()
        except (ssl.SSLError, OSError, socket.timeout) as e:
            result["issues"].append(str(e))
        return result
