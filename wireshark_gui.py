"""Safe launcher for the Wireshark desktop GUI on a selected interface."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


class WiresharkGUIError(RuntimeError):
    """Raised when the Wireshark desktop GUI cannot be located or launched."""


def resolve_wireshark(executable: str = "wireshark") -> str:
    """Resolve Wireshark from PATH, a user-supplied path, or common Windows paths."""
    candidate = (executable or "").strip().strip('"')
    # A tshark.exe path is commonly entered for the embedded monitor; infer sibling GUI.
    if candidate.lower().endswith("tshark.exe") and Path(candidate).is_file():
        sibling = str(Path(candidate).with_name("Wireshark.exe"))
        if Path(sibling).is_file():
            return sibling
    if candidate.lower() in {"tshark", "tshark.exe"}:
        tshark_path = shutil.which(candidate)
        if tshark_path:
            sibling = str(Path(tshark_path).with_name("Wireshark.exe"))
            if Path(sibling).is_file():
                return sibling
    if candidate and Path(candidate).is_file():
        path = Path(candidate)
        if path.name.lower() == "wireshark.exe":
            return str(path.resolve())
        if path.name.lower() == "tshark.exe":
            sibling = path.with_name("Wireshark.exe")
            if sibling.is_file():
                return str(sibling.resolve())
    if candidate and shutil.which(candidate):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env_name)
        if base:
            candidate_path = Path(base) / "Wireshark" / "Wireshark.exe"
            if candidate_path.is_file():
                return str(candidate_path)
    raise WiresharkGUIError(
        "Wireshark desktop GUI was not found. Install Wireshark, or enter the full path "
        "to Wireshark.exe (usually C:\\Program Files\\Wireshark\\Wireshark.exe)."
    )


def launch_wireshark_gui(executable: str, interface_identifier: str) -> str:
    """Open Wireshark and request live capture on the selected interface, without a shell."""
    if not interface_identifier or not str(interface_identifier).strip():
        raise WiresharkGUIError("Choose a capture interface before opening Wireshark.")
    path = resolve_wireshark(executable)
    args = [path, "-i", str(interface_identifier), "-k"]
    try:
        subprocess.Popen(
            args,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
        )
    except FileNotFoundError as exc:
        raise WiresharkGUIError("Wireshark.exe was not found at the resolved path. Check the installation path.") from exc
    except PermissionError as exc:
        raise WiresharkGUIError("Windows denied permission to launch Wireshark. Check application permissions.") from exc
    except OSError as exc:
        raise WiresharkGUIError(f"Could not launch Wireshark: {exc}") from exc
    return path
