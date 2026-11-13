// Host-side helper: never print SRT errors, paths, credentials or tool output.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
const [operation, receiptPath] = process.argv.slice(2);
try {
  const receipt = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
  const location = path.join(receipt.directory, 'node_modules/@anthropic-ai/sandbox-runtime');
  const srt = await import(pathToFileURL(path.join(location, 'dist/index.js')));
  const srtWin = srt.resolveSrtWin({ path: srt.VENDORED_SRT_WIN_EXE });
  let result;
  if (operation === 'windows-install') {
    result = await srt.installWindowsSandboxAsync({ ...receipt.windows, srtWin, skipProfileGrant: true });
    if (result.cancelled) throw Error('cancelled');
    console.log(JSON.stringify({ ok: true, helper: srt.VENDORED_SRT_WIN_EXE }));
  } else if (operation === 'cleanup') {
    const dirtyPath = path.join(path.dirname(receiptPath), 'windows-dirty.json');
    if (fs.existsSync(dirtyPath)) {
      const dirty = JSON.parse(fs.readFileSync(dirtyPath, 'utf8'));
      const ownerPath = path.join(dirty.directory, 'owner.json');
      if (fs.existsSync(ownerPath)) {
        const owner = JSON.parse(fs.readFileSync(ownerPath, 'utf8'));
        const user = await srt.getWindowsSandboxUserStatusAsync({ srtWin });
        const options = { srtWin, holderPid: owner.pid, sandboxUserSid: user.sid };
        if (!user.sid || !srt.revokeWindowsAclChecked(options).complete) throw Error('revoke');
        const restored = srt.restoreWindowsAcl(options);
        if (!Array.isArray(restored) || restored.some(o => !['revoked', 'restored', 'noRow', 'gone', 'relocated'].includes(o.status))) throw Error('restore');
      }
    }
    // Remove retained grants too. Exit zero can mean an unavailable volume is
    // still pending, so independently require an explicit empty grant status.
    const r = spawnSync(srt.VENDORED_SRT_WIN_EXE, ['acl', 'forget', '--all', '--json'], { encoding: 'utf8', timeout: 15000, windowsHide: true });
    if (r.status !== 0) throw Error('cleanup');
    const status = spawnSync(srt.VENDORED_SRT_WIN_EXE, ['user', 'status', '--json'], { encoding: 'utf8', timeout: 15000, windowsHide: true });
    if (status.status !== 0 || JSON.parse(status.stdout).persistent_grants?.state !== 'none') throw Error('pending');
    console.log(JSON.stringify({ ok: true }));
  } else if (operation === 'dependencies') {
    // Native checks include namespace and Windows fence support. No provider IO.
    const check = await srt.SandboxManager.checkDependenciesAsync();
    console.log(JSON.stringify({ ok: check.errors.length === 0, errors: check.errors.length, warnings: check.warnings.length }));
  } else throw Error('operation');
} catch {
  console.log(JSON.stringify({ ok: false }));
  process.exitCode = 1;
}
