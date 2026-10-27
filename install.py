"""Source checkout entrypoint; also works after pip installation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
try:
    from local_appsec_lab.install import main
except ImportError:
    raise SystemExit("Install the CLI first: python -m pip install .") from None

if __name__ == "__main__":
    raise SystemExit(main())
