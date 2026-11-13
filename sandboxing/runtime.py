"""Request-owned SRT sessions. Off mode never resolves or probes SRT.

The gateway remains the authority. SRT only confines the process it dispatches;
the original command, assignment and tool approvals are still checked upstream.
"""
from contextlib import asynccontextmanager
from dataclasses import dataclass
import asyncio
import base64
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import time

import anyio
import psutil

from guardrails.policy import PolicyDenied, digest
from .activity import Busy, directory, lease
from .models import ConnectionProfile, PROFILE_REVISION, SRT_VERSION

RESOURCES = Path(__file__).with_name("resources")
BRAVE = ["npx", "-y", "@brave/brave-search-mcp-server@2.1.4", "--transport", "stdio"]
GOOGLE = ["uvx", "--from", "analytics-mcp==1.0.0", "analytics-mcp"]
PRIVATE_NETWORKS = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "192.0.0.0/24", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "::ffff:0:0/96"]


def platform_support():
    return "experimental" if sys.platform == "win32" else "supported" if sys.platform in {"darwin", "linux"} else "unsupported"


def contained(path, parent):
    return Path(path).resolve().is_relative_to(Path(parent).resolve())


def protected(root):
    root = Path(root).resolve()
    return [root / ".env", root / ".local/mcp-auth", root / ".local/backups", root / ".local/conversations.sqlite", root / ".local/adk.sqlite", root / ".local/guardrails.sqlite", Path.home() / ".ssh", Path.home() / ".aws", Path.home() / ".config/gcloud"]


def validate_profile(root, profile):
    """Additional grants never expose a containing directory of private state."""
    root = Path(root).resolve()
    forbidden = [*protected(root), root / ".local", root / ".git", root / ".codex", root / ".agents"]
    for spelling in [*profile.read_paths, *profile.write_paths]:
        path = Path(spelling).resolve()
        if not path.exists():
            raise ValueError("Sandbox paths must exist before they can be reviewed.")
        if any(path == p.resolve() or contained(path, p) or contained(p, path) for p in forbidden):
            raise ValueError("Sandbox access cannot include private application files or directories containing them.")
        if spelling in profile.write_paths and any(contained(p, path) or contained(path, p) for p in [Path(sys.prefix), Path(sys.base_prefix), RESOURCES, directory(root)]):
            raise ValueError("Sandbox runtime and application dependencies must remain read-only.")
        if spelling in profile.write_paths and (contained(path, root) or contained(root, path)):
            raise ValueError("Additional write access must be outside the application workspace.")
    return profile


def maintained(spec):
    command = [spec.get("command"), *spec.get("args", [])]
    if command == BRAVE:
        return "brave"
    if command == GOOGLE and (spec.get("auth") or {}).get("type") == "google_adc":
        return "analytics"
    return None


def connection_profile(root, policy, name, spec):
    preset = maintained(spec)
    if preset:
        hosts = ["api.search.brave.com:443"] if preset == "brave" else ["oauth2.googleapis.com:443", "analyticsadmin.googleapis.com:443", "analyticsdata.googleapis.com:443", "www.googleapis.com:443"]
        return preset, ConnectionProfile(configuration_hash=digest(spec), destinations=hosts)
    profile = policy.sandbox.connections.get(name)
    if not profile or profile.configuration_hash != digest(spec):
        raise PolicyDenied("sandbox.profile", "Review this local connection’s sandbox access in Guardrails.")
    try:
        validate_profile(root, profile)
    except ValueError:
        raise PolicyDenied("sandbox.profile", "This connection’s sandbox paths need review.") from None
    return "custom", profile


def installation(root, *, checked=True):
    """Read a privately published receipt; never search PATH for an ambient SRT."""
    base = directory(root)
    try:
        receipt = json.loads((base / "current.json").read_text())
        location = Path(receipt["directory"])
        if not contained(location, base / "installations") or receipt["version"] != SRT_VERSION or receipt["profile_revision"] != PROFILE_REVISION:
            raise ValueError()
        manifest = json.loads((location / "node_modules/@anthropic-ai/sandbox-runtime/package.json").read_text())
        if manifest["version"] != SRT_VERSION or not Path(receipt["node"]).is_file():
            raise ValueError()
        if checked and (receipt.get("verified_platform") != sys.platform or not receipt.get("verified")):
            raise ValueError()
        if checked and sys.platform == "win32" and (base / "windows-dirty.json").exists():
            raise PolicyDenied("sandbox.cleanup", "Sandbox cleanup needs attention before another worker can start.")
        return receipt
    except PolicyDenied:
        raise
    except (OSError, ValueError, KeyError, TypeError):
        raise PolicyDenied("sandbox.setup", "Set up and check the local tool sandbox in Guardrails.") from None


def minimal_environment(work, command, extra=None):
    env = {k: os.environ[k] for k in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT") if k in os.environ}
    env.update(PATH=os.pathsep.join(dict.fromkeys([str(Path(command).parent), *os.defpath.split(os.pathsep)])), HOME=str(work), USERPROFILE=str(work), TEMP=str(work), TMP=str(work), TMPDIR=str(work), LANG="C.UTF-8", PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1", NODE_USE_ENV_PROXY="1", GCE_METADATA_DISABLED="true")
    for key, value in (extra or {}).items():
        name = key.upper()
        if name in {"PATH", "HOME", "USERPROFILE", "TEMP", "TMP", "TMPDIR", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH", "COMSPEC", "SYSTEMROOT", "WINDIR", "SHELL", "BASH_ENV", "ENV", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "RUBYOPT", "PERL5OPT"} or name.startswith(("DYLD_", "SRT_", "NODE_")) or "PROXY" in name:
            raise PolicyDenied("sandbox.environment", "Remove the reserved runtime environment mapping from this connection.")
        env[key] = value
    return env


def executable_reads(executable):
    """Include symlink names as well as their targets for metadata traversal.

    uv and Homebrew use intermediate directory links. Granting only realpath
    allows the executable's bytes but still denies readlink() on that route.
    """
    pending, result = [Path(executable).absolute()], []
    while pending and len(result) < 64:
        path = pending.pop()
        if path in result:
            continue
        result.append(path)
        for component in [path, *path.parents]:
            if component.is_symlink():
                if component not in result:
                    result.append(component)
                target = component.readlink()
                pending.append(target if target.is_absolute() else component.parent / target)
        resolved = path.resolve()
        if resolved not in result:
            pending.append(resolved)
    return result


def build_config(root, work, reads, writes, destinations, receipt):
    # Deny users' trees and app data, then expose exact dependency trees/files.
    # SRT allows read exceptions inside deny roots. Protected files get their own
    # narrower denies and can never be made readable by a custom grant.
    home = Path.home().resolve()
    deny = [str(home), str(Path(root).resolve()), str(Path(tempfile.gettempdir()).resolve()), *map(str, protected(root))]
    system_reads = []
    if sys.platform == "darwin":
        deny += ["/", "/Users", "/private/var/folders", "/tmp", "/private/tmp"]
        system_reads = ["/System", "/usr", "/bin", "/sbin", "/dev", "/Library/Apple", "/private/var/db/dyld", "/private/var/db/timezone", "/etc", "/private/etc"]
    elif sys.platform == "linux":
        deny += ["/", "/home", "/root", "/run/user", "/tmp", "/var/tmp", "/dev/shm"]
        system_reads = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/dev", "/proc", "/sys", "/etc/ssl/certs", "/etc/ld.so.cache", "/etc/nsswitch.conf", "/etc/hosts", "/etc/resolv.conf", "/etc/passwd", "/etc/group", "/etc/localtime"]
    paths = lambda items: [{"path": str(Path(p).absolute()), "literal": True} for p in dict.fromkeys(map(str, items))]
    config = {"filesystem": {"denyRead": paths(deny), "allowRead": paths([work, *system_reads, *reads]), "allowWrite": paths([work, *writes]), "denyWrite": paths([Path(root).resolve(), home, *reads, *protected(root)])}, "network": {"allowedDomains": destinations, "deniedDomains": ["localhost"], "deniedResolvedAddresses": PRIVATE_NETWORKS, "strictAllowlist": True, "allowLocalBinding": False, "allowAllUnixSockets": False}, "enableWeakerNestedSandbox": False, "enableWeakerNetworkIsolation": False, "allowNestedUserNamespaces": False, "allowAppleEvents": False}
    # The broad write deny above must not cover the invocation's own scratch
    # directory or approved extra write roots. SRT's write deny takes precedence.
    # Explicitly deny sensitive paths and all read-only runtime trees instead;
    # everything else is already denied by the write allowlist.
    own_paths = ["/tmp/claude", "/private/tmp/claude"] if sys.platform == "darwin" else ["/tmp/claude"] if sys.platform == "linux" else []
    config["filesystem"]["denyWrite"] = paths([*own_paths, *protected(root), *[p for p in reads if not any(contained(w, p) or contained(p, w) for w in [work, *writes])]])
    dependencies = receipt.get("dependencies", {})
    if dependencies.get("rg"):
        config["ripgrep"] = {"command": dependencies["rg"]}
    for name, key in [("bwrap", "bwrapPath"), ("socat", "socatPath")]:
        if dependencies.get(name):
            config[key] = dependencies[name]
    if sys.platform == "win32":
        config["windows"] = {**receipt["windows"], "srtWin": {"path": str(Path(receipt["directory"]) / "node_modules/@anthropic-ai/sandbox-runtime/vendor/srt-win/srt-win.exe")}}
        # Locate the package's actual architecture-specific helper in setup.
        config["windows"]["srtWin"]["path"] = receipt["windows_helper"]
    return config


@dataclass
class Prepared:
    argv: list[str]
    env: dict[str, str]
    cwd: str | None
    sandboxed: bool


async def stop_tree(process):
    """Stop only an owned subprocess tree, including detached descendants."""
    try:
        parent = psutil.Process(process.pid)
        children = parent.children(recursive=True)
    except psutil.Error:
        children = []
    for child in reversed(children):
        try:
            child.terminate()
        except psutil.Error:
            pass
    if process.returncode is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        await asyncio.wait_for(process.wait(), 2)
    except TimeoutError:
        process.kill()
        await process.wait()
    if children:
        _, alive = await asyncio.to_thread(psutil.wait_procs, children, timeout=1)
        for child in alive:
            try:
                child.kill()
            except psutil.Error:
                pass


async def bounded_command(argv, *, env=None, cwd=None, timeout=30, maximum=65536, input=None):
    """No shell, bounded output and cancellation-shielded process ownership."""
    process = await asyncio.create_subprocess_exec(*argv, env=env, cwd=cwd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, **({"start_new_session": True} if os.name != "nt" else {}))
    async def communicate():
        async def feed():
            try:
                if input:
                    process.stdin.write(input)
                    await process.stdin.drain()
                process.stdin.close()
            except (BrokenPipeError, ConnectionResetError):
                pass
        feeder = asyncio.create_task(feed())
        output = bytearray()
        try:
            while chunk := await process.stdout.read(min(65536, maximum + 1 - len(output))):
                output.extend(chunk)
                if len(output) > maximum:
                    raise PolicyDenied("sandbox.output", "The local worker returned too much output.")
            await feeder
            return await process.wait(), bytes(output)
        finally:
            feeder.cancel()
            await asyncio.gather(feeder, return_exceptions=True)
    try:
        async with asyncio.timeout(timeout):
            return await communicate()
    finally:
        with anyio.CancelScope(shield=True):
            await stop_tree(process)


class SandboxRunner:
    def __init__(self, root):
        self.root = Path(root).resolve()

    @asynccontextmanager
    async def prepare(self, argv, *, env=None, policy=None, connection="pdf", spec=None, credential_file=None, force=False, internal=False, profile_override=None, extra_reads=()):
        from guardrails.settings import load_policy
        current = load_policy(self.root)
        if policy and current.sandbox != policy.sandbox:
            raise PolicyDenied("policy.changed", "Saved settings changed before the local worker started.")
        enabled = force or current.sandbox.enabled
        # Windows ACL changes are shared across processes. Wait rather than
        # tearing down another request's active session.
        manager = None
        if not internal:
            deadline = time.monotonic() + 30
            while manager is None:
                try:
                    candidate = lease(self.root, "sandbox" if enabled else "local", serial=enabled and os.name == "nt")
                    candidate.__enter__()
                    manager = candidate
                except Busy:
                    if time.monotonic() >= deadline:
                        raise PolicyDenied("sandbox.busy", "Wait for the active local tool or sandbox setup to finish.") from None
                    await asyncio.sleep(.1)
        work = None
        tracker = None
        processes = {}
        record = None
        interruption = None
        try:
            # Recheck after obtaining the lease to close the toggle/launch race.
            latest = load_policy(self.root)
            if latest.revision != current.revision:
                raise PolicyDenied("policy.changed", "Saved settings changed before the local worker started.")
            if not enabled:
                self.audit(connection, "off", "started", current.revision)
                yield Prepared(list(argv), env or {}, None, False)
                self.audit(connection, "off", "completed", current.revision)
                return
            if platform_support() == "unsupported":
                raise PolicyDenied("sandbox.platform", "Sandboxing is not available on this operating system.")
            receipt = installation(self.root, checked=not internal)
            install = Path(receipt["directory"])
            # macOS AF_UNIX paths are limited to ~104 bytes. SRT creates its
            # proxy socket under TMPDIR, so a workspace-relative directory can
            # fail simply because the user's repository path is long.
            temporary_root = "/private/tmp" if sys.platform == "darwin" else "/tmp" if sys.platform == "linux" else tempfile.gettempdir()
            work = Path(tempfile.mkdtemp(prefix="ks-", dir=temporary_root))
            work.chmod(0o700)
            records = directory(self.root) / "workers"
            records.mkdir(exist_ok=True, mode=0o700)
            record = records / (work.name + ".json")
            record.write_text(json.dumps({"work":str(work),"pid":os.getpid(),"created":psutil.Process().create_time()}))
            record.chmod(0o600)
            (work / "tmp").mkdir(mode=0o700)
            scratch = work / "tmp"
            profile = profile_override
            kind = "pdf"
            if spec:
                kind, profile = connection_profile(self.root, current, connection, spec)
            profile = profile or ConnectionProfile(configuration_hash="0" * 64)
            command = list(argv)
            reads = [install, *executable_reads(receipt["node"]), Path(sys.base_prefix), Path(sys.prefix), *extra_reads, *profile.read_paths]
            if kind == "brave":
                command = [receipt["node"], str(install / "node_modules/@brave/brave-search-mcp-server/dist/index.js"), "--transport", "stdio"]
            elif kind == "analytics":
                python = install / "analytics" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
                if not python.is_file():
                    raise PolicyDenied("sandbox.setup", "Set up the maintained Analytics sandbox environment.")
                command = [str(python), "-I", str(RESOURCES / "analytics_entry.py")]
                reads += [RESOURCES / "analytics_entry.py", *executable_reads(python)]
            else:
                executable = shutil.which(command[0]) if not Path(command[0]).is_absolute() else command[0]
                if not executable:
                    raise PolicyDenied("sandbox.command", "The reviewed local command is not installed.")
                command[0] = str(Path(executable).absolute())
                reads += executable_reads(executable)
            extra = dict(env or {})
            if credential_file:
                # Never expose the directory holding the vault database/key.
                target = scratch / "google-credentials.json"
                shutil.copyfile(credential_file, target)
                target.chmod(0o600)
                extra["GOOGLE_APPLICATION_CREDENTIALS"] = str(target)
            config = build_config(self.root, scratch, reads, profile.write_paths, profile.destinations, receipt)
            if os.name == "nt":
                config["filesystem"]["allowRead"].append({"path": str(RESOURCES / "exec.mjs"), "literal": True})
            settings = work / "settings.json"
            settings.write_text(json.dumps(config))
            settings.chmod(0o600)
            environment = minimal_environment(scratch, receipt["node"], extra)
            environment["PATH"] = os.pathsep.join(dict.fromkeys([*[str(Path(p).parent) for p in receipt.get("dependencies", {}).values()], *environment["PATH"].split(os.pathsep)]))
            if os.name == "nt":
                (directory(self.root) / "windows-dirty.json").write_text(json.dumps({"directory": str(work)}))
            launch = [receipt["node"], str(install / "node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js"), "--settings", str(settings), "--", *command]
            if os.name == "nt":
                encoded = base64.urlsafe_b64encode(json.dumps(command).encode()).decode().rstrip("=")
                launch = [receipt["node"], str(RESOURCES / "windows-launch.mjs"), str(install / "node_modules/@anthropic-ai/sandbox-runtime/dist/index.js"), str(settings), str(RESOURCES / "exec.mjs"), encoded]
            launch = [launch[0], str(RESOURCES / "owner.mjs"), str(work / "owner.json"), *launch[1:]]
            request_task = asyncio.current_task()
            async def track():
                nonlocal interruption
                while True:
                    if not internal:
                        try:
                            with sqlite3.connect(self.root / ".local/guardrails.sqlite", timeout=.1) as database:
                                stopped = database.execute("SELECT value FROM flags WHERE name='stopped'").fetchone()
                            if stopped and stopped[0] == '1':
                                interruption = ("runtime.stopped", "Emergency stop is active.")
                            elif load_policy(self.root).revision != current.revision:
                                interruption = ("policy.changed", "Saved settings changed during local execution.")
                        except Exception:
                            interruption = ("policy.changed", "Could not verify the current local execution settings.")
                        if interruption:
                            request_task.cancel()
                            return
                    try:
                        owner = json.loads((work / "owner.json").read_text())
                        process = psutil.Process(owner["pid"])
                        if 0 <= owner["started"] - process.create_time() < 30:
                            for child in [process, *process.children(recursive=True)]:
                                processes[child.pid] = child.create_time()
                    except (OSError, ValueError, KeyError, psutil.Error):
                        pass
                    await asyncio.sleep(.05)
            tracker = asyncio.create_task(track())
            self.audit(connection, "on", "started", current.revision)
            yield Prepared(launch, environment, str(scratch), True)
            self.audit(connection, "on", "completed", current.revision)
        except BaseException as error:
            self.audit(connection, "on" if enabled else "off", "blocked", current.revision)
            if isinstance(error, asyncio.CancelledError) and interruption:
                raise PolicyDenied(*interruption) from None
            raise
        finally:
            with anyio.CancelScope(shield=True):
                try:
                    if tracker:
                        tracker.cancel()
                        await asyncio.gather(tracker, return_exceptions=True)
                    await self.cleanup_processes(processes)
                    if work and os.name == "nt":
                        await self.windows_cleanup()
                finally:
                    clean = os.name != 'nt' or not (directory(self.root) / 'windows-dirty.json').exists()
                    if work and clean:
                        shutil.rmtree(work, ignore_errors=True)
                    if manager:
                        manager.__exit__(None, None, None)
                    if record and clean:
                        record.unlink(missing_ok=True)

    @staticmethod
    async def cleanup_processes(processes):
        owned = []
        for pid, created in processes.items():
            try:
                process = psutil.Process(pid)
                if process.create_time() == created and process.status() != psutil.STATUS_ZOMBIE:
                    owned.append(process)
                    process.terminate()
            except psutil.Error:
                pass
        if owned:
            _, alive = await asyncio.to_thread(psutil.wait_procs, owned, timeout=1)
            for process in alive:
                try:
                    process.kill()
                except psutil.Error:
                    pass

    async def recover(self):
        """Remove abandoned private workspaces only after their owner is dead."""
        if os.name == 'nt' and (directory(self.root) / 'windows-dirty.json').exists():
            await self.windows_cleanup()
        for record in (directory(self.root) / "workers").glob("ks-*.json"):
            try:
                value = json.loads(record.read_text())
                try:
                    parent = psutil.Process(value["pid"])
                    if parent.create_time() == value["created"] and parent.status() != psutil.STATUS_ZOMBIE:
                        continue
                except psutil.Error:
                    pass
                work = Path(value["work"])
                temporary_root = Path("/private/tmp" if sys.platform == "darwin" else "/tmp" if sys.platform == "linux" else tempfile.gettempdir()).resolve()
                if work.parent.resolve() != temporary_root or not work.name.startswith("ks-") or work.is_symlink():
                    raise ValueError()
                try:
                    owner = json.loads((work / "owner.json").read_text())
                    process = psutil.Process(owner["pid"])
                    if 0 <= owner["started"] - process.create_time() < 30 and str(work / "owner.json") in process.cmdline():
                        await self.cleanup_processes({p.pid:p.create_time() for p in [process,*process.children(recursive=True)]})
                except (OSError, KeyError, ValueError, psutil.Error):
                    pass
                shutil.rmtree(work, ignore_errors=True)
                record.unlink(missing_ok=True)
            except (OSError, ValueError, KeyError):
                raise PolicyDenied("sandbox.cleanup", "An abandoned sandbox workspace needs administrator review.") from None

    def audit(self, connection, mode, outcome, revision):
        from guardrails.runtime import Runtime
        from guardrails.policy import Decision
        Runtime(self.root).record({}, Decision(action="block" if outcome == "blocked" else "allow", rule=f"sandbox.{mode}.{outcome}.{PROFILE_REVISION}", explanation="Local worker lifecycle.", revision=revision), connection or "local")

    async def windows_cleanup(self):
        try:
            receipt = json.loads((directory(self.root) / "current.json").read_text())
            code, output = await bounded_command([receipt["node"], str(RESOURCES / "maintenance.mjs"), "cleanup", str(directory(self.root) / "current.json")], env=setup_environment(), timeout=20)
            if code or json.loads(output).get("ok") is not True:
                raise ValueError()
            (directory(self.root) / "windows-dirty.json").unlink(missing_ok=True)
        except (OSError, ValueError, KeyError, TimeoutError):
            raise PolicyDenied("sandbox.cleanup", "Sandbox permissions could not be cleaned up. Use Check again in Guardrails.") from None

    async def run(self, argv, *, input=None, timeout=7, maximum=1024 * 1024, **kwargs):
        async with self.prepare(argv, **kwargs) as prepared:
            return await bounded_command(prepared.argv, env=prepared.env, cwd=prepared.cwd, input=input, timeout=timeout, maximum=maximum)


def setup_environment():
    """Package-manager commands must never inherit provider keys or loaders."""
    return {key: value for key, value in os.environ.items() if key in {"PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "LANG"}}
