"""Safe, local TShark live-capture helpers for LogScout-SH.

Captures packet metadata only; it does not write PCAP files or collect payload bytes.
Use only on interfaces/networks you are authorized to monitor.
"""
from __future__ import annotations

import atexit
import csv
import io
import os
import queue
import shutil
import subprocess
import threading
from datetime import datetime, timezone
from typing import Any


class TSharkError(RuntimeError):
    """Raised when TShark is unavailable or capture cannot be started."""


FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
    "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "dns.qry.name",
]


def resolve_tshark(executable: str = "tshark") -> str:
    """Resolve TShark from PATH or an explicitly supplied executable path."""
    candidate = (executable or "tshark").strip().strip('"')
    if not candidate:
        candidate = "tshark"
    resolved = shutil.which(candidate)
    if resolved:
        return resolved
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return os.path.abspath(candidate)
    raise TSharkError(
        "TShark was not found. Install Wireshark with the TShark component, then "
        "restart the terminal/app. If it is installed but not on PATH, enter the "
        "full path to tshark.exe in the Network Monitor settings."
    )


def _run_checked(args: list[str], timeout: int = 15) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise TSharkError("TShark executable was not found. Check the executable path.") from exc
    except subprocess.TimeoutExpired as exc:
        raise TSharkError("TShark did not respond in time. Check the installation and try again.") from exc
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "No details were returned.").strip()
        raise TSharkError(f"TShark command failed: {message[:700]}")
    return result


def get_tshark_version(executable: str = "tshark") -> str:
    path = resolve_tshark(executable)
    result = _run_checked([path, "--version"], timeout=10)
    return (result.stdout.splitlines() or ["TShark version available"])[0].strip()


def list_interfaces(executable: str = "tshark") -> list[dict[str, str]]:
    """Return interface IDs and readable labels from `tshark -D`."""
    path = resolve_tshark(executable)
    result = _run_checked([path, "-D"], timeout=15)
    interfaces: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Preserve the exact identifier TShark accepts after the numeric index.
        head = line.split(".", 1)
        if len(head) != 2 or not head[0].strip().isdigit():
            continue
        index = head[0].strip()
        rest = head[1].strip()
        identifier = rest.split(" (", 1)[0].strip()
        label = rest
        if identifier:
            interfaces.append({"id": index, "identifier": identifier, "label": label})
    if not interfaces:
        raise TSharkError(
            "TShark is installed, but no capture interfaces were listed. Check the Npcap "
            "installation and Windows capture permissions."
        )
    return interfaces


def parse_packet_line(line: str) -> dict[str, Any] | None:
    """Parse one CSV-formatted TShark metadata row; ignore malformed rows."""
    try:
        row = next(csv.reader(io.StringIO(line)))
    except (csv.Error, StopIteration):
        return None
    if len(row) != len(FIELDS):
        return None
    try:
        epoch = float(row[1]) if row[1] else None
        timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat() if epoch is not None else None
        frame_number = int(row[0]) if row[0] else None
        frame_length = int(row[2]) if row[2] else None
    except (ValueError, OverflowError, OSError):
        return None
    src = row[4] or row[5] or "—"
    dst = row[6] or row[7] or "—"
    protocols = row[3] or "unknown"
    return {
        "frame_number": frame_number,
        "timestamp": timestamp,
        "length_bytes": frame_length,
        "protocols": protocols,
        "source": src,
        "destination": dst,
        "source_port": row[8] or row[10] or "",
        "destination_port": row[9] or row[11] or "",
        "dns_query": row[12] or "",
    }


class LiveCapture:
    """Owns one TShark process and safely queues parsed packet metadata."""
    def __init__(self, executable: str, interface_id: str):
        self.executable = resolve_tshark(executable)
        self.interface_id = str(interface_id)
        self.events: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=5000)
        self.process: subprocess.Popen[str] | None = None
        self.reader_thread: threading.Thread | None = None
        self.stderr_thread: threading.Thread | None = None
        self._stderr = ""
        self._lock = threading.Lock()
        atexit.register(self.stop)

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def start(self) -> None:
        if self.running:
            return
        args = [self.executable, "-n", "-l", "-i", self.interface_id, "-T", "fields", "-E", "separator=,", "-E", "quote=d"]
        for field in FIELDS:
            args.extend(["-e", field])
        try:
            self.process = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
                creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
            )
        except FileNotFoundError as exc:
            raise TSharkError("TShark executable was not found. Check the configured path.") from exc
        except PermissionError as exc:
            raise TSharkError("Windows denied access to the capture interface. Check Npcap and capture permissions.") from exc
        except OSError as exc:
            raise TSharkError(f"Could not start TShark: {exc}") from exc
        self.reader_thread = threading.Thread(target=self._read_stdout, daemon=True, name="LogScout-TShark-stdout")
        self.stderr_thread = threading.Thread(target=self._read_stderr, daemon=True, name="LogScout-TShark-stderr")
        self.reader_thread.start()
        self.stderr_thread.start()

    def _put(self, item: dict[str, Any]) -> None:
        try:
            self.events.put_nowait(item)
        except queue.Full:
            try:
                self.events.get_nowait()
            except queue.Empty:
                pass
            try:
                self.events.put_nowait(item)
            except queue.Full:
                pass

    def _read_stdout(self) -> None:
        process = self.process
        if process is None or process.stdout is None:
            return
        for line in process.stdout:
            packet = parse_packet_line(line.rstrip("\r\n"))
            if packet is not None:
                self._put({"kind": "packet", "packet": packet})
        code = process.poll()
        if code not in (None, 0):
            with self._lock:
                detail = self._stderr.strip()
            self._put({"kind": "error", "message": detail[:700] or f"TShark exited with code {code}. Check Npcap and capture permissions."})

    def _read_stderr(self) -> None:
        process = self.process
        if process is None or process.stderr is None:
            return
        chunks: list[str] = []
        for line in process.stderr:
            chunks.append(line)
            if sum(map(len, chunks)) > 4000:
                chunks = ["".join(chunks)[-4000:]]
        with self._lock:
            self._stderr = "".join(chunks)

    def drain(self, limit: int = 1000) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for _ in range(max(1, limit)):
            try:
                items.append(self.events.get_nowait())
            except queue.Empty:
                break
        return items

    def stop(self) -> None:
        process = self.process
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
        for thread in (self.reader_thread, self.stderr_thread):
            if thread and thread.is_alive():
                thread.join(timeout=1)
        for stream in (process.stdout, process.stderr):
            if stream:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
        self.process = None

