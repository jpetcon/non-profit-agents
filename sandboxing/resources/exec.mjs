// Runs INSIDE the sandbox. Never interprets the reviewed arguments as a shell.
import { spawn } from 'node:child_process';
const argv = JSON.parse(Buffer.from(process.argv[2], 'base64url').toString('utf8'));
const child = spawn(argv[0], argv.slice(1), { shell: false, stdio: 'inherit', env: process.env });
child.on('error', () => { process.exitCode = 1; });
child.on('exit', code => { process.exitCode = code ?? 1; });
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
