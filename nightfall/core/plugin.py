import os
import importlib
import inspect
import pkgutil


class BasePlugin:
    name = "base"
    version = "0.1"
    description = "Base plugin class"

    def __init__(self):
        self.enabled = True

    def run(self, target):
        raise NotImplementedError("Plugin must implement run()")

    def should_run(self, target):
        return True

    def info(self):
        return {"name": self.name, "version": self.version,
                "description": self.description, "enabled": self.enabled}


class PluginManager:
    def __init__(self):
        self.plugins = {}

    def register(self, plugin):
        self.plugins[plugin.name] = plugin

    def get(self, name):
        return self.plugins.get(name)

    def list_plugins(self):
        return {n: p.info() for n, p in self.plugins.items()}

    def run_all(self, target):
        results = {}
        for name, plugin in self.plugins.items():
            if plugin.enabled and plugin.should_run(target):
                try:
                    results[name] = plugin.run(target)
                except Exception as e:
                    results[name] = {"error": str(e)}
        return results


def discover_plugins(plugin_dir=None):
    manager = PluginManager()
    if plugin_dir is None:
        import nightfall.plugins
        module_path = os.path.dirname(nightfall.plugins.__file__)
    else:
        module_path = plugin_dir

    for importer, modname, ispkg in pkgutil.iter_modules([module_path]):
        if ispkg:
            continue
        try:
            module = importlib.import_module(f"nightfall.plugins.{modname}")
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and issubclass(obj, BasePlugin)
                        and obj is not BasePlugin):
                    instance = obj()
                    manager.register(instance)
        except Exception:
            pass

    return manager
