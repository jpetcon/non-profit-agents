"""FastMCP adapter preserving per-request ownership and protocol streams."""
from contextlib import asynccontextmanager
from pathlib import Path
import os

from fastmcp.client.transports import StdioTransport
from .runtime import SandboxRunner


class LocalStdioTransport(StdioTransport):
    def __init__(self, *, root=None, connection=None, spec=None, policy=None, **kwargs):
        super().__init__(**kwargs)
        self.root, self.connection, self.spec, self.policy = root, connection, spec, policy

    @asynccontextmanager
    async def connect_session(self, **kwargs):
        if self.root is None:
            async with super().connect_session(**kwargs) as session:
                yield session
            return
        runner = SandboxRunner(self.root)
        async with runner.prepare([self.command, *self.args], env=self.env, policy=self.policy, connection=self.connection, spec=self.spec, credential_file=(self.env or {}).get("GOOGLE_APPLICATION_CREDENTIALS")) as prepared:
            if not prepared.sandboxed:
                async with super().connect_session(**kwargs) as session:
                    yield session
            else:
                # A fresh SDK transport owns the SRT process and all streams.
                # The SDK performs bounded, cancellation-shielded tree cleanup.
                transport = StdioTransport(command=prepared.argv[0], args=prepared.argv[1:], env=prepared.env, cwd=prepared.cwd, keep_alive=False, log_file=Path(os.devnull))
                async with transport.connect_session(**kwargs) as session:
                    yield session
