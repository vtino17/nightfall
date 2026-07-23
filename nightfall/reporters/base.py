from abc import ABC, abstractmethod


class BaseReporter(ABC):
    def __init__(self, output_path=None):
        self.output_path = output_path

    @abstractmethod
    def generate(self, findings, metadata=None):
        pass

    @abstractmethod
    def format_name(self):
        pass

    def save(self, findings, metadata=None):
        output = self.generate(findings, metadata)
        if self.output_path:
            with open(self.output_path, "w", encoding="utf-8") as f:
                f.write(output)
        return output
