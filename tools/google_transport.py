"""Request-owned Google credential files for trusted local MCP subprocesses."""
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import secrets

import anyio
import psutil
from sandboxing.transport import LocalStdioTransport

from .mcp_auth import AuthenticationRequired, validate_google_credentials


def clean_abandoned_credentials(directory):
    for path in Path(directory).glob("adc-*.json"):
        try:
            _, pid, created, _ = path.stem.split("-", 3)
            process = psutil.Process(int(pid))
            if int(process.create_time()) == int(created) and process.is_running():
                continue
        except (ValueError, psutil.Error):
            pass
        path.unlink(missing_ok=True)


class GoogleStdioTransport(LocalStdioTransport):
    def __init__(self, handle, *, command, args, env, project, **sandbox):
        self.handle, self.explicit_env, self.project = handle, env, project
        super().__init__(command=command, args=args, env={}, keep_alive=False, log_file=Path(os.devnull), **sandbox)

    @asynccontextmanager
    async def connect_session(self, **kwargs):
        saved = self.handle.read()
        if not saved.get("connected"):
            raise AuthenticationRequired(self.handle.name)
        credentials = validate_google_credentials(saved.get("google"))
        credentials["scopes"] = ["https://www.googleapis.com/auth/analytics.readonly"]
        path = self.handle.vault.directory / f"adc-{os.getpid()}-{int(psutil.Process().create_time())}-{secrets.token_hex(16)}.json"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(credentials, stream)
            self.env = {**self.explicit_env, "GOOGLE_APPLICATION_CREDENTIALS": str(path), "GCE_METADATA_DISABLED": "true"}
            if self.project:
                self.env["GOOGLE_CLOUD_PROJECT"] = self.project
                self.env["GOOGLE_CLOUD_QUOTA_PROJECT"] = self.project
            self.handle.read()
            async with super().connect_session(**kwargs) as session:
                async with anyio.create_task_group() as group:
                    async def watch_disconnect():
                        while True:
                            await anyio.sleep(.2)
                            self.handle.read()
                    group.start_soon(watch_disconnect)
                    try:
                        yield session
                    finally:
                        group.cancel_scope.cancel()
        finally:
            self.env = {}
            path.unlink(missing_ok=True)
