import json
import http.server
import urllib.parse
from datetime import datetime, timezone


class APIHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/":
            self._html(self._index_html())
        elif parsed.path == "/health":
            self._json({"status": "ok", "version": "1.0.0"})
        elif parsed.path == "/api/stats":
            self._json({"total_scans": 0, "total_vulns": 0, "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0}})
        elif parsed.path == "/api/history":
            self._json([])
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else "{}"

        if parsed.path == "/api/scan":
            data = json.loads(body)
            self._json({"message": "scan queued", "target": data.get("target", ""), "id": datetime.now(timezone.utc).isoformat()})
        elif parsed.path == "/api/schedule":
            data = json.loads(body)
            self._json({"message": "scheduled", "target": data.get("target", ""), "interval": data.get("interval", "daily")})
        else:
            self._json({"error": "not found"}, 404)

    def _json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _html(self, content, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def _index_html(self):
        return """<!DOCTYPE html>
<html lang="en">
<head><title>Nightfall</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:20px 40px;border-bottom:1px solid #30363d}
h1{font-size:24px;color:#58a6ff}
.container{max-width:1200px;margin:0 auto;padding:30px 40px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px;margin-bottom:30px}
.stat{padding:20px;background:#161b22;border:1px solid #30363d;border-radius:8px}
.stat-value{font-size:32px;font-weight:bold;color:#58a6ff}
.stat-label{font-size:14px;color:#8b949e;margin-top:5px}
.btn{display:inline-block;padding:10px 20px;background:#238636;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:14px}
.btn:hover{background:#2ea043}
input,select{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px;color:#c9d1d9;width:100%;margin-bottom:10px}
label{display:block;margin-bottom:5px;color:#8b949e;font-size:14px}
table{width:100%;border-collapse:collapse;margin-top:10px}
th{text-align:left;padding:10px;color:#8b949e;font-size:12px;text-transform:uppercase;border-bottom:1px solid #30363d}
td{padding:10px;border-bottom:1px solid #21262d}
.badge{padding:2px 8px;border-radius:12px;font-size:12px}
.critical{background:#da3633;color:#fff}
.high{background:#d29922;color:#fff}
.medium{background:#1f6feb;color:#fff}
.low{background:#238636;color:#fff}
</style></head>
<body>
<header><h1>Nightfall</h1><p style="color:#8b949e;font-size:14px">Vulnerability Scanning Framework</p></header>
<div class="container">
<div class="grid">
<div class="stat"><div class="stat-value" id="totalScans">0</div><div class="stat-label">Total Scans</div></div>
<div class="stat"><div class="stat-value" id="totalVulns">0</div><div class="stat-label">Vulnerabilities</div></div>
<div class="stat"><div class="stat-value" id="criticalCount">0</div><div class="stat-label">Critical</div></div>
<div class="stat"><div class="stat-value" id="highCount">0</div><div class="stat-label">High</div></div>
</div>

<div class="card">
<h2>New Scan</h2>
<form id="scanForm">
<label>Target (IP or hostname)</label>
<input type="text" id="targetInput" placeholder="10.0.0.1 or example.com">
<label>Ports</label>
<input type="text" id="portsInput" value="80,443,22,3389,8080">
<button type="submit" class="btn">Start Scan</button>
</form>
</div>

<div class="card">
<h2>Scan History</h2>
<table><thead><tr><th>Target</th><th>Date</th><th>Status</th><th>Findings</th></tr></thead>
<tbody id="historyBody"><tr><td colspan="4" style="text-align:center;color:#8b949e">No scans yet</td></tr></tbody></table>
</div>
</div>

<script>
fetch('/api/stats').then(r=>r.json()).then(d=>{
document.getElementById('totalScans').textContent=d.total_scans;
document.getElementById('totalVulns').textContent=d.total_vulns;
document.getElementById('criticalCount').textContent=d.severity_breakdown.critical;
document.getElementById('highCount').textContent=d.severity_breakdown.high;
});
document.getElementById('scanForm').addEventListener('submit',function(e){
e.preventDefault();
fetch('/api/scan',{method:'POST',body:JSON.stringify({target:document.getElementById('targetInput').value,ports:document.getElementById('portsInput').value})}).then(r=>r.json()).then(d=>alert('Scan queued: '+d.target));
});
</script>
</body></html>"""


def start_ui(host="0.0.0.0", port=8080):
    server = http.server.HTTPServer((host, port), APIHandler)
    print(f"Nightfall UI: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
