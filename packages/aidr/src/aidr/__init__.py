"""Python access to OpenSecura dependency scans and guardrail assessments."""

from .client import AIDR, AsyncAIDR, GuardrailError, ScanError

__version__ = "0.1.0"
__all__ = ["AIDR", "AsyncAIDR", "GuardrailError", "ScanError"]


def main() -> int:
    from .cli import main as cli_main

    return cli_main()
