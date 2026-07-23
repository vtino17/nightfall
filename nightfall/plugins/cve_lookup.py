import json
import urllib.request
import urllib.error
import re


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVELookup:
    def __init__(self, cache=None):
        self.cache = cache or {}
        self._local_db = self._build_local_db()

    def _build_local_db(self):
        return {
            ("openssh", "7.2p2"): [{"id": "CVE-2016-6210", "score": 4.3, "severity": "medium", "description": "OpenSSH user enumeration via timing differences"}],
            ("openssh", "7.4"): [{"id": "CVE-2017-15906", "score": 5.0, "severity": "medium", "description": "OpenSSH DoS via MaxStartups limit bypass"}],
            ("apache", "2.4.49"): [{"id": "CVE-2021-41773", "score": 7.5, "severity": "high", "description": "Apache HTTP Server path traversal"}],
            ("apache", "2.4.50"): [{"id": "CVE-2021-42013", "score": 9.0, "severity": "critical", "description": "Apache HTTP Server path traversal bypass"}],
            ("vsftpd", "2.3.4"): [{"id": "CVE-2011-2523", "score": 10.0, "severity": "critical", "description": "vsftpd backdoor triggered by :) smiley"}],
            ("nginx", "1.14.0"): [{"id": "CVE-2019-20372", "score": 6.1, "severity": "medium", "description": "Nginx directory traversal via misconfigured alias"}],
            ("php", "5.6.30"): [{"id": "CVE-2018-5711", "score": 5.0, "severity": "medium", "description": "PHP GD GdImageCreateFromGifCtx infinite loop"}],
            ("mysql", "8.0.27"): [{"id": "CVE-2022-21367", "score": 4.9, "severity": "medium", "description": "MySQL Server crash via specially crafted input"}],
            ("postgresql", "9.6.0"): [{"id": "CVE-2017-7486", "score": 6.5, "severity": "high", "description": "PostgreSQL pg_user_mappings privilege escalation"}],
        }

    def query(self, service, version):
        key = (service.lower().strip(), version.strip())
        if key in self._local_db:
            return self._local_db[key]
        if key in self.cache:
            return self.cache[key]
        try:
            results = self._nvd_query(service, version)
            self.cache[key] = results
            return results
        except Exception:
            return []

    def enrich(self, result):
        if not result.get("banner"):
            result["cve_results"] = []
            return result
        service = result.get("service", "unknown").lower()
        version = self._extract_version(result["banner"])
        if version:
            cves = self.query(service, version)
            result["cve_results"] = cves
            for cve in cves:
                result.setdefault("vulnerabilities", []).append({
                    "id": cve["id"],
                    "name": cve.get("description", cve["id"]),
                    "severity": cve.get("severity", "medium"),
                    "score": cve.get("score", 0),
                    "source": "nvd"
                })
        return result

    def _extract_version(self, banner):
        m = re.search(r"(\d+\.\d+(?:\.\d+)?(?:p\d+)?)", banner)
        return m.group(1) if m else None

    def _nvd_query(self, service, version, timeout=10):
        keyword = f"{service} {version}"
        encoded = urllib.parse.quote(keyword)
        url = f"{NVD_API_BASE}?keywordSearch={encoded}&resultsPerPage=5"
        req = urllib.request.Request(url, headers={"User-Agent": "Nightfall/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return self._parse_nvd_response(data)
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            return []

    def _parse_nvd_response(self, data):
        results = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            metrics = cve.get("metrics", {})
            base_score = None
            if "cvssMetricV31" in metrics:
                base_score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", 0)
            elif "cvssMetricV30" in metrics:
                base_score = metrics["cvssMetricV30"][0]["cvssData"].get("baseScore", 0)
            elif "cvssMetricV2" in metrics:
                base_score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", 0)
            severity = "info"
            if base_score and base_score >= 9.0:
                severity = "critical"
            elif base_score and base_score >= 7.0:
                severity = "high"
            elif base_score and base_score >= 4.0:
                severity = "medium"
            elif base_score:
                severity = "low"
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            results.append({
                "id": cve.get("id", ""),
                "score": base_score or 0,
                "severity": severity,
                "description": desc[:200]
            })
        return results
