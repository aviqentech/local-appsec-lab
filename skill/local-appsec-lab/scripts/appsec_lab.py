"""Portable helper: installed bundled engine or source-checkout engine."""

import sys
from pathlib import Path

sys.dont_write_bytecode = True
skill = Path(__file__).resolve().parent.parent
runtime = skill / "runtime"
source = skill.parent.parent / "src"
if (runtime / "local_appsec_lab").is_dir():
    sys.path.insert(0, str(runtime))
elif (source / "local_appsec_lab").is_dir():
    sys.path.insert(0, str(source))
from local_appsec_lab.cli import main  # noqa: E402

raise SystemExit(main())
