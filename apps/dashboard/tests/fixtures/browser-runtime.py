"""Select source fixtures or verify an explicitly installed production tenant."""

import json
import importlib.util
import os
from pathlib import Path
import runpy
import sys


def prepare():
    root = Path(__file__).resolve().parents[4]
    supplied = os.environ.get("OPENAIDR_TEST_INSTALLED_TENANT")
    if not supplied:
        sys.path[:0] = [str(root / "src"), str(root / "packages/common/src")]
        return lambda: None
    tenant = json.loads(supplied)
    directory = root / "dependencies/api-runtime"
    record = runpy.run_path(str(root / "scripts/verify_public_dependencies.py"))["verify"](directory)
    checks = runpy.run_path(str(root / "tests/customer_api/artifacts.py"))
    build = checks["tenant_identity"](tenant, record)

    def verify():
        assert importlib.util.find_spec("openaidr_api") is None, "Service package in production browser fixture"
        roots = {"openaidr": checks["package_bytes"]("openaidr", Path(tenant["wheel"]), build)}
        for role in ("sdk", "common"):
            pin = record["wheels"][role]
            namespace = pin["distribution"].replace("-", "_")
            roots[namespace] = checks["package_bytes"](namespace, directory / pin["name"], pin["source"])
        checks["loaded_origins"](roots)

    verify()
    return verify
