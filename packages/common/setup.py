"""Build shared helpers with the repository's canonical source identity."""

import json
import os
from pathlib import Path
import runpy
import sys

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT.parents[1]
HELPER = ROOT / "_build_support.py"
if not HELPER.is_file():
    HELPER = SOURCE / "src/openaidr/build_info.py"
metadata = runpy.run_path(str(HELPER))
saved = ROOT / "src/openaidr_common/_build.json"
if saved.is_file():
    info = metadata["validate"](json.loads(saved.read_text()))
    for key, value in metadata["environment"](info).items():
        if os.environ.get(key) and os.environ[key] != value:
            raise ValueError("supplied build identity does not match the source archive")
else:
    # Artifacts need a clean checkout; metadata and editable installs serve the working tree.
    info = metadata["resolve"](SOURCE, clean=metadata["requires_clean_source"](sys.argv))


class BuildPython(build_py):
    def run(self):
        super().run()
        (Path(self.build_lib) / "openaidr_common/_build.json").write_text(json.dumps(info) + "\n")


class SourceDistribution(sdist):
    def make_release_tree(self, base_dir, files):
        super().make_release_tree(base_dir, files)
        target = Path(base_dir)
        (target / "_build_support.py").write_bytes(HELPER.read_bytes())
        (target / "src/openaidr_common/_build.json").write_text(json.dumps(info) + "\n")


setup(version=info["version"], cmdclass={"build_py": BuildPython, "sdist": SourceDistribution})
