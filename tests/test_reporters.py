import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nightfall.reporters.factory import ReporterFactory
from nightfall.reporters.json_reporter import JSONReporter
from nightfall.reporters.html_reporter import HTMLReporter


SAMPLE_FINDINGS = [
    {
        "host": "192.168.1.1",
        "port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "status": "open",
        "banner": "SSH-2.0-OpenSSH_7.4",
        "vulnerabilities": [
            {"id": "CVE-2017-15906", "name": "SSH DoS", "severity": "medium"}
        ],
    },
    {
        "host": "192.168.1.1",
        "port": 443,
        "protocol": "tcp",
        "service": "https",
        "status": "closed",
        "vulnerabilities": [],
    },
]


class TestJSONReporter:
    def test_generates_valid_json(self):
        r = JSONReporter()
        output = r.generate(SAMPLE_FINDINGS)
        data = json.loads(output)
        assert "findings" in data
        assert "summary" in data
        assert len(data["findings"]) == 2

    def test_summary_counts(self):
        r = JSONReporter()
        output = r.generate(SAMPLE_FINDINGS)
        data = json.loads(output)
        s = data["summary"]
        assert s["total_targets"] == 2
        assert s["open_ports"] == 1
        assert s["closed_ports"] == 1
        assert s["total_vulnerabilities"] == 1

    def test_save_to_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        r = JSONReporter(output_path=path)
        r.save(SAMPLE_FINDINGS)
        with open(path) as f:
            data = json.load(f)
        assert "findings" in data
        os.unlink(path)


class TestFactory:
    def test_create_json_reporter(self):
        r = ReporterFactory.create("json")
        assert isinstance(r, JSONReporter)

    def test_create_html_reporter(self):
        r = ReporterFactory.create("html")
        assert isinstance(r, HTMLReporter)
