"""Copy built frontends into the Python package before building a wheel."""

from pathlib import Path
import shutil

root = Path(__file__).resolve().parents[1]
for app in ("console", "admin"):
    source = root / "apps" / app / "dist"
    target = root / "src" / "openaidr" / "web" / app / "dist"
    if target.exists():
        shutil.rmtree(target)
    if (source / "index.html").is_file():
        shutil.copytree(source, target)
    else:
        print(
            f"{app}: no frontend build found; wheel will serve an explanatory 404. Run make web first."
        )
