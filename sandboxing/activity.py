"""Cross-process activity leases and a short, OS-locked configuration gate.

Leases also cover normal (unsandboxed) launches so switching modes cannot race a
connection test in the dashboard or a worker in the separate gateway process.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets

import psutil


class Busy(ValueError):
    pass


def directory(root):
    path = Path(root) / ".local/sandbox"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


@contextmanager
def gate(root):
    path = directory(root) / "activity.lock"
    with path.open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise Busy("A local tool or sandbox change is starting. Try again.") from None
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def leases(root):
    path = directory(root) / "leases"
    path.mkdir(exist_ok=True, mode=0o700)
    result = []
    for file in path.glob("*.json"):
        try:
            value = json.loads(file.read_text())
            process = psutil.Process(value["pid"])
            if process.create_time() == value["created"] and process.status() != psutil.STATUS_ZOMBIE:
                result.append(value)
                continue
        except (OSError, ValueError, KeyError, psutil.Error):
            pass
        file.unlink(missing_ok=True)
    return result


def require_idle(root):
    if leases(root):
        raise Busy("Finish or stop the current response, connection test or sandbox setup before changing sandbox settings.")


@contextmanager
def lease(root, kind, *, serial=False):
    with gate(root):
        active = leases(root)
        if any(v["kind"] == "setup" for v in active) or (serial and any(v['kind'] in {'local', 'sandbox'} for v in active)) or (kind == "setup" and active):
            raise Busy("A sandbox operation is already running. Wait for it to finish.")
        value = {"pid": os.getpid(), "created": psutil.Process().create_time(), "kind": kind}
        path = directory(root) / "leases" / (secrets.token_hex(16) + ".json")
        from control_panel.store import atomic_write
        atomic_write(path, json.dumps(value), private=True)
    try:
        yield
    finally:
        path.unlink(missing_ok=True)
