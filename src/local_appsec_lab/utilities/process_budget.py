"""Aggregate native-process group and scratch budgets; Docker uses cgroups instead."""

import os
import stat
import subprocess
import time
from pathlib import Path

from local_appsec_lab.errors import BudgetExceeded


class ProcessBudget:
    def __init__(self, process, directory, limits):
        self.process, self.directory, self.limits = process, directory, limits
        self.checked = 0

    def __call__(self):
        if time.monotonic() - self.checked < 0.2:
            return
        self.checked = time.monotonic()
        # Only group IDs and aggregate counters are read, never other command lines.
        process_list = subprocess.run(
            ["/bin/ps", "-axo", "pgid=,rss="], capture_output=True, timeout=3
        )
        if process_list.returncode:
            raise BudgetExceeded("Cannot supervise native scanner resource usage")
        memory, count = 0, 0
        for line in process_list.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == str(self.process.pid).encode():
                memory += int(parts[1]) * 1024
                count += 1
        if memory > self.limits.memory_mb * 1048576 or count > self.limits.processes:
            raise BudgetExceeded("Native scanner process/memory budget exceeded")
        size, files = 0, 0
        for directory, directories, names in os.walk(self.directory, followlinks=False):
            directories[:] = [d for d in directories if not (Path(directory) / d).is_symlink()]
            for name in names:
                try:
                    info = (Path(directory) / name).lstat()
                except FileNotFoundError:
                    continue
                if stat.S_ISREG(info.st_mode):
                    size += info.st_size
                    files += 1
                    if size > self.limits.storage_mb * 1048576 or files > 10000:
                        raise BudgetExceeded("Native scanner scratch budget exceeded")
