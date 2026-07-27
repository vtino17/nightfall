import argparse
import sys
import json
from datetime import datetime, timezone


def build_parser():
    p = argparse.ArgumentParser(description="Nightfall - Vulnerability Scanning Framework")
    s = p.add_subparsers(dest="command")

    sc = s.add_parser("scan", help="Run a vulnerability scan")
    sc.add_argument("target", help="IP, hostname, or CIDR")
    sc.add_argument("--ports", default="21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,27017")
    sc.add_argument("--output", "-o", default=None)
    sc.add_argument("--format", "-f", choices=["json", "html", "csv", "sarif"], default="json")
    sc.add_argument("--cve", action="store_true")
    sc.add_argument("--severity", choices=["critical", "high", "medium", "low"], default="medium")
    sc.add_argument("--rate", type=int, default=100)
    sc.add_argument("--timeout", type=int, default=5)
    sc.add_argument("--plugins", nargs="+", default=None)
    sc.add_argument("--verbose", "-v", action="store_true")

    pl = s.add_parser("plugins", help="List plugins")
    pl.add_argument("--list", action="store_true")

    sch = s.add_parser("schedule", help="Schedule scans")
    sch.add_argument("--target", required=True)
    sch.add_argument("--interval", choices=["hourly", "daily", "weekly"], default="daily")
    sch.add_argument("--notify", choices=["email", "slack", "webhook"])
    sch.add_argument("--time", default="02:00")

    ui = s.add_parser("ui", help="Start web dashboard")
    ui.add_argument("--port", type=int, default=8080)
    ui.add_argument("--host", default="0.0.0.0")

    rp = s.add_parser("report", help="Generate report")
    rp.add_argument("input", help="Input JSON file")
    rp.add_argument("--format", choices=["html", "pdf", "sarif"], default="html")
    rp.add_argument("--output", "-o", default=None)

    return p


def entry_point():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        from nightfall.core.scanner import Scanner
        from nightfall.core.target import TargetParser
        from nightfall.core.discovery import ServiceDiscovery
        from nightfall.reporters.factory import ReporterFactory

        targets = TargetParser.parse(args.target, args.ports)
        print(f"Targets: {len(targets)}", file=sys.stderr)

        discovery = ServiceDiscovery(rate=args.rate, timeout=args.timeout)
        results = []
        for t in targets:
            r = discovery.identify(t)
            results.append(r)

        scanner = Scanner()
        scan_results = scanner.analyze(results, cve_lookup=args.cve, severity=args.severity)

        reporter = ReporterFactory.create(args.format)
        out = args.output or f"nightfall_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.{args.format}"
        reporter.generate(scan_results, out)
        print(f"Report: {out}", file=sys.stderr)

    elif args.command == "plugins":
        from nightfall.core.plugin import discover_plugins
        for p in discover_plugins():
            print(f"  {p.name}: {p.description}")

    elif args.command == "schedule":
        from nightfall.scheduler.manager import Scheduler
        s = Scheduler()
        s.add(args.target, args.interval, args.time, args.notify)
        print(f"Scheduled {args.interval} scan for {args.target} at {args.time}")

    elif args.command == "ui":
        from nightfall.ui.server import start_ui
        print(f"Starting Nightfall UI on http://{args.host}:{args.port}")
        start_ui(args.host, args.port)

    elif args.command == "report":
        from nightfall.reporters.factory import ReporterFactory
        with open(args.input) as f:
            data = json.load(f)
        reporter = ReporterFactory.create(args.format)
        out = args.output or f"nightfall_report.{args.format}"
        reporter.generate(data, out)
        print(f"Report: {out}", file=sys.stderr)


if __name__ == "__main__":
    entry_point()
