import socket
import concurrent.futures
import ssl
import time


SERVICE_PORT_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap",
    389: "ldap", 443: "https", 445: "smb", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 27017: "mongodb"
}


class ServiceDiscovery:
    def __init__(self, timeout=3):
        self.timeout = timeout

    def identify(self, target):
        if target.port is None:
            target.status = "scanned"
            target.service = "unknown"
            return target
        result = self._check_port(target.host, target.port, target.protocol)
        target.status = result.get("status", "closed")
        target.service = result.get("service", "unknown")
        target.banner = result.get("banner")
        return target

    def identify_many(self, targets, workers=100):
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(self.identify, t): t for t in targets}
            for fut in concurrent.futures.as_completed(futs):
                try:
                    results.append(fut.result())
                except Exception:
                    t = futs[fut]
                    t.status = "error"
                    t.service = "unknown"
                    results.append(t)
        results.sort(key=lambda t: (t.host or "", t.port or 0))
        return results

    def _check_port(self, host, port, protocol="tcp"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((host, port))
            service = SERVICE_PORT_MAP.get(port, "unknown")
            banner = self._grab_banner(sock, port, protocol)
            sock.close()
            return {"port": port, "status": "open", "service": service, "banner": banner}
        except (socket.timeout, ConnectionRefusedError, OSError):
            return {"port": port, "status": "closed", "service": None, "banner": None}
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _grab_banner(self, sock, port, protocol):
        try:
            if port in (443, 8443):
                return self._tls_banner(sock)
            sock.sendall(b"\r\n")
            time.sleep(0.5)
            data = sock.recv(1024)
            banner = data.decode("utf-8", errors="replace").strip()
            return banner[:500] if banner else None
        except (socket.timeout, OSError):
            return None

    def _tls_banner(self, sock):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssock = ctx.wrap_socket(sock, server_hostname="")
            cert = ssock.getpeercert()
            ssock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = ssock.recv(1024)
            return data.decode("utf-8", errors="replace").strip()[:500]
        except (ssl.SSLError, OSError):
            return None
