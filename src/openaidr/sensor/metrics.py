"""Nonblocking measurements of the long-running sensor process."""

import psutil


class ProcessMetrics:
    def __init__(self):
        self.process = None
        self.cpu_ready = False

    def sample(self):
        result = dict(cpu_percent=None, memory_rss_bytes=None)
        if self.process is None:
            try:
                self.process = psutil.Process()
            except (psutil.Error, OSError):
                return result
        try:
            cpu = self.process.cpu_percent(interval=None)
            # The first call establishes the CPU baseline; it is not an idle sample.
            if self.cpu_ready:
                result["cpu_percent"] = cpu
            self.cpu_ready = True
        except (psutil.Error, OSError):
            self.cpu_ready = False
        try:
            result["memory_rss_bytes"] = self.process.memory_info().rss
        except (psutil.Error, OSError):
            pass
        return result
