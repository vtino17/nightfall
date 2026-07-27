import sqlite3
import json
import os
from datetime import datetime, timezone


class ScanDatabase:
    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "..", "nightfall.db")
        self.db_path = os.path.abspath(db_path)
        self._init_db()

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    targets TEXT NOT NULL,
                    ports TEXT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    duration_ms INTEGER,
                    status TEXT DEFAULT 'running',
                    summary TEXT,
                    error TEXT
                );
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER,
                    protocol TEXT DEFAULT 'tcp',
                    service TEXT,
                    status TEXT,
                    banner TEXT,
                    vulnerabilities TEXT DEFAULT '[]',
                    raw_result TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                );
                CREATE INDEX IF NOT EXISTS idx_results_scan_id ON results(scan_id);
                CREATE INDEX IF NOT EXISTS idx_results_host ON results(host);
                CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
            """)

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def create_scan(self, name, targets, ports=None):
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO scans (name, targets, ports, started_at, status) VALUES (?, ?, ?, ?, ?)",
                [name, json.dumps(targets), ports, datetime.now(timezone.utc).isoformat(), "running"],
            )
            return cur.lastrowid

    def complete_scan(self, scan_id, duration_ms, summary, error=None):
        with self._conn() as conn:
            conn.execute(
                "UPDATE scans SET completed_at=?, duration_ms=?, status=?, summary=?, error=? WHERE id=?",
                [datetime.now(timezone.utc).isoformat(), duration_ms, "complete" if not error else "failed",
                 json.dumps(summary), error, scan_id],
            )

    def save_result(self, scan_id, result):
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO results (scan_id, host, port, protocol, service, status, banner, vulnerabilities, raw_result) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [scan_id, result.get("host"), result.get("port"), result.get("protocol", "tcp"),
                 result.get("service"), result.get("status"), result.get("banner"),
                 json.dumps(result.get("vulnerabilities", [])), json.dumps(result)],
            )

    def get_scan(self, scan_id):
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id=?", [scan_id]).fetchone()
            if not row:
                return None
            results = conn.execute("SELECT * FROM results WHERE scan_id=?", [scan_id]).fetchall()
            return self._row_to_dict(row, results)

    def list_scans(self, limit=20):
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, name, started_at, completed_at, status, duration_ms FROM scans ORDER BY id DESC LIMIT ?",
                [limit],
            ).fetchall()
            return [dict(r) for r in rows]

    def _row_to_dict(self, scan_row, result_rows):
        scan = dict(scan_row)
        if scan.get("targets"):
            try:
                scan["targets"] = json.loads(scan["targets"])
            except (json.JSONDecodeError, TypeError):
                pass
        if scan.get("summary"):
            try:
                scan["summary"] = json.loads(scan["summary"])
            except (json.JSONDecodeError, TypeError):
                pass
        scan["results"] = [dict(r) for r in result_rows]
        for r in scan["results"]:
            if r.get("vulnerabilities"):
                try:
                    r["vulnerabilities"] = json.loads(r["vulnerabilities"])
                except (json.JSONDecodeError, TypeError):
                    pass
        return scan
