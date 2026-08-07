from nightfall.core.scanner import Scanner
from nightfall.core.target import ScanTarget


def test_sensitive_service_is_detected_even_when_banner_is_present():
    target = ScanTarget("127.0.0.1", 23)
    target.status = "open"
    target.service = "telnet"
    target.banner = "Welcome to the test service"

    result = Scanner().analyze([target], severity="medium")[0]

    assert any(finding["id"] == "PORT-002" for finding in result["vulnerabilities"])
