"""Python access to OpenSecura dependency scans and guardrail assessments."""

from .client import AIDR, AsyncAIDR, GuardrailError, ScanError

__version__ = "0.1.0"
__all__ = ["AIDR", "AsyncAIDR", "GuardrailError", "ScanError"]


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="OpenSecura Python SDK for dependency scans and guardrails.")
    parser.add_argument("--version", action="version", version=__version__)
    parser.parse_args()
    parser.print_help()
    print("\nPython usage: from aidr import AIDR, AsyncAIDR")
    return 0
