import time
import threading
import json
import os
from datetime import datetime, timedelta


class ScanSchedule:
    def __init__(self, name, targets, interval_hours, ports=None, plugins=None):
        self.name = name
        self.targets = targets
        self.interval_hours = interval_hours
        self.ports = ports
        self.plugins = plugins or []
        self.last_run = None
        self.next_run = datetime.utcnow()
        self.enabled = True

    def to_dict(self):
        return {
            "name": self.name,
            "targets": self.targets,
            "interval_hours": self.interval_hours,
            "ports": self.ports,
            "plugins": self.plugins,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data):
        s = cls(data["name"], data["targets"], data["interval_hours"],
                ports=data.get("ports"), plugins=data.get("plugins"))
        if data.get("last_run"):
            s.last_run = datetime.fromisoformat(data["last_run"])
        if data.get("next_run"):
            s.next_run = datetime.fromisoformat(data["next_run"])
        s.enabled = data.get("enabled", True)
        return s


class SchedulerManager:
    def __init__(self, scan_fn, state_path=None):
        self.scan_fn = scan_fn
        self.state_path = state_path or os.path.join(os.path.dirname(__file__), "..", "scheduler_state.json")
        self.schedules = []
        self._running = False
        self._thread = None

    def add_schedule(self, schedule):
        self.schedules.append(schedule)

    def remove_schedule(self, name):
        self.schedules = [s for s in self.schedules if s.name != name]

    def get_schedule(self, name):
        for s in self.schedules:
            if s.name == name:
                return s
        return None

    def start(self):
        if self._running:
            return
        self._running = True
        self._load_state()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        self._save_state()

    def _loop(self):
        while self._running:
            now = datetime.utcnow()
            for schedule in self.schedules:
                if schedule.enabled and now >= schedule.next_run:
                    try:
                        self.scan_fn(schedule)
                        schedule.last_run = now
                    except Exception:
                        pass
                    schedule.next_run = now + timedelta(hours=schedule.interval_hours)
            self._save_state()
            time.sleep(30)

    def _save_state(self):
        try:
            data = {"saved_at": datetime.utcnow().isoformat(),
                    "schedules": [s.to_dict() for s in self.schedules]}
            with open(self.state_path, "w") as f:
                json.dump(data, f, indent=2)
        except OSError:
            pass

    def _load_state(self):
        try:
            with open(self.state_path) as f:
                data = json.load(f)
            self.schedules = [ScanSchedule.from_dict(s) for s in data.get("schedules", [])]
        except (OSError, json.JSONDecodeError):
            pass
