"""Trusted native launcher; set inherited OS limits before entering the OS sandbox."""

import json
import os
import resource
import sys

limits = json.loads(sys.argv[1])
resource.setrlimit(resource.RLIMIT_CPU, (limits["duration_seconds"], limits["duration_seconds"]))
resource.setrlimit(resource.RLIMIT_FSIZE, (limits["log_bytes"], limits["log_bytes"]))
resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
if sys.platform == "linux":
    maximum = limits["memory_mb"] * 1048576
    resource.setrlimit(resource.RLIMIT_AS, (maximum, maximum))
os.execvpe(sys.argv[2], sys.argv[2:], dict(os.environ))
