import platform
import sys


def identify_platform():
    return {
        "operating_system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "python_executable": sys.executable
    }