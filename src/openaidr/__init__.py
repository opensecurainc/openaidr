"""OpenAIDR: Agentic AI Detection and Response."""

def __getattr__(name):
    if name == "__version__":
        from .build_info import current

        return current()["version"]
    raise AttributeError(name)
