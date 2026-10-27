import runpy
import sys
from pathlib import Path

sys.argv.extend(["--operation", "uninstall"])
runpy.run_path(str(Path(__file__).resolve().parent.parent / "install.py"), run_name="__main__")
