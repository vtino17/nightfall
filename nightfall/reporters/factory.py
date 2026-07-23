from nightfall.reporters.json_reporter import JSONReporter
from nightfall.reporters.html_reporter import HTMLReporter


class ReporterFactory:
    _registry = {}

    @classmethod
    def register(cls, name, reporter_class):
        cls._registry[name.lower()] = reporter_class

    @classmethod
    def create(cls, format_name, output_path=None):
        name = format_name.lower().strip()
        if name in cls._registry:
            return cls._registry[name](output_path=output_path)
        raise ValueError(f"Unknown report format: {format_name}. Available: {list(cls._registry.keys())}")

    @classmethod
    def available_formats(cls):
        return list(cls._registry.keys())


ReporterFactory.register("json", JSONReporter)
ReporterFactory.register("html", HTMLReporter)
