import sys

from nightfall.cli import build_parser, entry_point
from nightfall.core.discovery import ServiceDiscovery
from nightfall.core.target import ScanTarget, TargetParser
from nightfall.reporters.factory import ReporterFactory


def test_scan_command_uses_instance_parser_and_batch_discovery(monkeypatch, tmp_path):
    observed = {}

    def parse(self, target, ports):
        assert isinstance(self, TargetParser)
        observed["target"] = target
        observed["ports"] = ports
        return [ScanTarget("127.0.0.1", 443)]

    def identify_many(self, targets, workers):
        observed["workers"] = workers
        targets[0].status = "closed"
        return targets

    class Reporter:
        def generate(self, results, output):
            observed["results"] = results
            observed["output"] = output

    monkeypatch.setattr(TargetParser, "parse", parse)
    monkeypatch.setattr(ServiceDiscovery, "identify_many", identify_many)
    monkeypatch.setattr(ReporterFactory, "create", lambda _format: Reporter())
    monkeypatch.setattr(sys, "argv", [
        "nightfall", "scan", "127.0.0.1", "--ports", "443",
        "--rate", "4", "--output", str(tmp_path / "report.json"),
    ])

    entry_point()

    assert observed["target"] == "127.0.0.1"
    assert observed["ports"] == "443"
    assert observed["workers"] == 4
    assert len(observed["results"]) == 1


def test_scan_limits_must_be_positive():
    parser = build_parser()
    try:
        parser.parse_args(["scan", "127.0.0.1", "--rate", "0"])
        assert False, "zero worker count should be rejected"
    except SystemExit as error:
        assert error.code == 2
