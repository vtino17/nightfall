import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nightfall.core.target import ScanTarget
from nightfall.core.discovery import ServiceDiscovery


class TestServiceDiscovery:
    def setup_method(self):
        self.disc = ServiceDiscovery(timeout=1)

    def test_identify_closed_port(self):
        target = ScanTarget("127.0.0.1", 65535)
        self.disc.identify(target)
        assert target.status == "closed"

    def test_identify_many_empty(self):
        results = self.disc.identify_many([])
        assert results == []

    def test_identify_single(self):
        target = ScanTarget("127.0.0.1", 1)
        self.disc.identify(target)
        assert target.status in ("closed", "open")

    def test_service_port_mapping_ssh(self):
        from nightfall.core.discovery import SERVICE_PORT_MAP
        assert SERVICE_PORT_MAP[22] == "ssh"
        assert SERVICE_PORT_MAP[80] == "http"
        assert SERVICE_PORT_MAP[443] == "https"

    def test_propagates_discovered_banner_to_scan_target(self):
        target = ScanTarget("example.com", 22)
        self.disc._check_port = lambda *_args: {
            "status": "open",
            "service": "ssh",
            "banner": "SSH-2.0-OpenSSH_7.4",
        }

        result = self.disc.identify(target)
        assert result.banner == "SSH-2.0-OpenSSH_7.4"
