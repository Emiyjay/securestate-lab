import platform
import socket
import sys
import os
from datetime import datetime, timezone


def identify_platform():
    """Collect basic operating system and runtime information."""

    return {
        "operating_system": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor() or "Unknown",
        "hostname": socket.gethostname(),
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
        "current_user": os.environ.get("USERNAME", "Unknown"),
        "assessment_time_utc": datetime.now(
            timezone.utc
        ).isoformat(),
    }