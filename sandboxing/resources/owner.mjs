// Host-side ownership record. The confined child cannot access this directory.
// Preserves the published CLI on POSIX and the literal-argv adapter on Windows.
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
const [record, entry, ...args] = process.argv.slice(2);
fs.writeFileSync(record, JSON.stringify({ pid: process.pid, started: Date.now()/1000 }), { mode: 0o600 });
process.argv = [process.execPath, entry, ...args];
await import(pathToFileURL(entry));
