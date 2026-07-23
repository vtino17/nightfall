# Nightfall

Modular vulnerability scanning framework with plugin architecture, web dashboard, multi-format reporting, scheduled scanning, and notifications.

## Features

- TCP port scanning with service fingerprinting
- CVE correlation via NVD API
- SSL/TLS certificate inspection
- Plugin system for custom vulnerability checks
- HTML dark-theme dashboard
- JSON report output
- Slack and email notifications
- SQLite-backed scan history
- Scheduled recurring scans
- Web UI dashboard

## Quick Start

```bash
git clone https://github.com/vtino17/nightfall.git
cd nightfall
pip install -e .
pip install cryptography
```

## Usage

### CLI Scanning

```bash
nightfall scan target.com
nightfall scan 10.0.0.0/24 --ports 80,443,22 --cve
nightfall scan example.com --format html --output report.html
```

### Web Dashboard

```bash
nightfall ui --port 8080
```

### Scheduled Scanning

```bash
nightfall schedule --target example.com --interval daily --notify slack
```

## Architecture

```
nightfall/
  core/         Scanner engine, target parsing, service discovery
  plugins/      CVE lookup, SSL checks, extensible
  reporters/    JSON, HTML, CSV output
  notifiers/    Slack, email alerts
  database/     SQLite scan persistence
  scheduler/    Recurring task management
  ui/           Web dashboard
```

## Tests

```bash
pip install pytest
pytest tests/ -v
```

## License

MIT
