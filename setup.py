"""Generate immutable package metadata through the standard setuptools backend."""

import json
from pathlib import Path
import runpy
import sys

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist

ROOT = Path(__file__).resolve().parent
metadata = runpy.run_path(str(ROOT / "src/openaidr/build_info.py"))
# Artifacts require a clean checkout. Metadata commands and editable installs
# serve the working tree, where uncommitted changes are the point.
info = metadata["resolve"](ROOT, clean=metadata["requires_clean_source"](sys.argv))


class BuildPython(build_py):
    def run(self):
        super().run()
        (Path(self.build_lib) / "openaidr/_build.json").write_text(json.dumps(info) + "\n")


class SourceDistribution(sdist):
    def make_release_tree(self, base_dir, files):
        super().make_release_tree(base_dir, files)
        build = self.get_finalized_command("build_py")
        (Path(base_dir) / build.get_package_dir("openaidr") / "_build.json").write_text(json.dumps(info) + "\n")


setup(version=info["version"], cmdclass={"build_py": BuildPython, "sdist": SourceDistribution})
