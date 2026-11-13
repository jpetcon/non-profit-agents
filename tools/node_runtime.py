"""Locate the Node distribution installed by uv, independently of system PATH."""
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
import os
from pathlib import Path


class NodeRuntimeError(ValueError):
    pass


@dataclass(frozen=True)
class NodeRuntime:
    node: Path
    npm_cli: Path
    version: str


def bundled_node() -> NodeRuntime:
    """Return native Node and npm JS paths, rather than Python CLI wrappers.

    uv run supplies the environment's node/npm/npx wrappers to normal tools.
    SRT needs the native executable and an explicit npm script during setup.
    Neither path is inferred from a user's nvm or global npm installation.
    """
    try:
        from nodejs_wheel.executable import ROOT_DIR
        root = Path(ROOT_DIR)
        node = root / 'node.exe' if os.name == 'nt' else root / 'bin/node'
        npm_cli = root / 'lib/node_modules/npm/bin/npm-cli.js'
        package_version = version('nodejs-wheel-binaries')
        if not node.is_file() or not npm_cli.is_file():
            raise NodeRuntimeError()
        return NodeRuntime(node.resolve(), npm_cli.resolve(), package_version)
    except (ImportError, OSError, PackageNotFoundError, NodeRuntimeError):
        raise NodeRuntimeError(
            'Kindred’s bundled tools need repair. Stop Kindred, run uv sync, '
            'then start it with uv run python -m control_panel.'
        ) from None
