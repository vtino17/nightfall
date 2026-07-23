import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nightfall.core.target import ScanTarget, TargetParser


class TestScanTarget:
    def test_create_with_host_only(self):
        t = ScanTarget("192.168.1.1")
        assert t.host == "192.168.1.1"
        assert t.port is None
        assert t.protocol == "tcp"

    def test_create_with_port(self):
        t = ScanTarget("10.0.0.1", 443)
        assert t.host == "10.0.0.1"
        assert t.port == 443

    def test_defaults(self):
        t = ScanTarget("example.com")
        assert t.status == "unknown"
        assert t.service is None
        assert t.vulnerabilities == []

    def test_equality(self):
        a = ScanTarget("1.2.3.4", 80)
        b = ScanTarget("1.2.3.4", 80)
        c = ScanTarget("1.2.3.4", 443)
        assert a == b
        assert a != c

    def test_hashable(self):
        t = ScanTarget("1.2.3.4", 80)
        s = {t}
        assert t in s


class TestTargetParser:
    def setup_method(self):
        self.parser = TargetParser()

    def test_parse_single_ip(self):
        targets = self.parser.parse("192.168.1.1")
        assert len(targets) == 1
        assert targets[0].host == "192.168.1.1"

    def test_parse_multiple_targets(self):
        targets = self.parser.parse("10.0.0.1 10.0.0.2")
        assert len(targets) == 2
        assert targets[0].host == "10.0.0.1"
        assert targets[1].host == "10.0.0.2"

    def test_parse_with_ports(self):
        targets = self.parser.parse("192.168.1.1", "80,443")
        assert len(targets) == 2
        assert targets[0].port == 80
        assert targets[1].port == 443

    def test_parse_port_range(self):
        targets = self.parser.parse("10.0.0.1", "80-82")
        assert len(targets) == 3
        assert targets[0].port == 80
        assert targets[1].port == 81
        assert targets[2].port == 82

    def test_parse_hostname(self):
        targets = self.parser.parse("scanme.nmap.org")
        assert len(targets) == 1
        assert targets[0].host == "scanme.nmap.org"

    def test_parse_invalid_raises(self):
        try:
            self.parser.parse("not!valid")
            assert False, "Should have raised"
        except ValueError:
            pass

    def test_parse_comma_separated(self):
        targets = self.parser.parse("10.0.0.1,10.0.0.2")
        assert len(targets) == 2
