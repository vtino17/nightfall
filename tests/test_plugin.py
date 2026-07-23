import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nightfall.core.plugin import BasePlugin, PluginManager, discover_plugins
from nightfall.core.target import ScanTarget


class TestPlugin:
    def test_base_plugin_abstract(self):
        p = BasePlugin()
        try:
            p.run(None)
            assert False, "Should raise NotImplementedError"
        except NotImplementedError:
            pass

    def test_plugin_manager(self):
        class TestP(BasePlugin):
            name = "test"
            def run(self, target):
                return {"ok": True}

        mgr = PluginManager()
        mgr.register(TestP())
        assert "test" in mgr.list_plugins()
        target = ScanTarget("127.0.0.1", 80)
        results = mgr.run_all(target)
        assert results["test"]["ok"] is True
