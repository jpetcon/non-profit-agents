// The 0.0.81 CLI quotes for POSIX before selecting cmd.exe on Windows. Keep the
// command out of cmd altogether: the inner executable is a Node argv shim.
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
const [modulePath, settingsPath, shim, encoded] = process.argv.slice(2);
const { SandboxManager } = await import(pathToFileURL(modulePath));
let child;
try {
  await SandboxManager.initialize(JSON.parse(fs.readFileSync(settingsPath, 'utf8')));
  const wrapped = await SandboxManager.wrapWithSandboxArgv('kindred', { exe: process.execPath, args: [shim, encoded] });
  child = spawn(wrapped.argv[0], wrapped.argv.slice(1), { shell: false, stdio: 'inherit', env: wrapped.env });
  const code = await new Promise(resolve => {
    child.on('error', () => resolve(1));
    child.on('exit', code => resolve(code ?? 1));
    for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
  });
  await SandboxManager.reset();
  process.exitCode = code;
} catch {
  child?.kill();
  await SandboxManager.reset();
  process.exitCode = 1;
}
