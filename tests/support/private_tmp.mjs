// Portable private temp root for test fixtures.
//
// Production storage checks (issuer state, OIDC store, audit log, events)
// reject any ancestor that another principal can write. A default Linux /tmp
// (mode 1777) and some macOS TMPDIR chains are therefore unusable. Use the
// platform temp directory only when its whole literal and resolved ancestor
// chain is owner/root-only; otherwise fall back to a private 0700 root inside
// this repository's tests directory (already used by other fixtures).
import { lstatSync, realpathSync, mkdirSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

function safeChain(path) {
  const uid = process.getuid();
  for (const chain of [path, realpathSync(path)]) {
    for (let node = chain; ; node = dirname(node)) {
      const stat = lstatSync(node);
      if (stat.isSymbolicLink()) { if (stat.uid !== 0) return false; }
      else if (!stat.isDirectory() || ![0, uid].includes(stat.uid) || (stat.mode & 0o022)) return false;
      if (node === dirname(node)) break;
    }
  }
  return true;
}

let root;
export function privateTmpdir() {
  if (root) return root;
  const system = tmpdir();
  if (safeChain(system)) return (root = system);
  const local = join(dirname(fileURLToPath(import.meta.url)), '..', '.private-tmp');
  mkdirSync(local, { recursive: true, mode: 0o700 });
  chmodSync(local, 0o700);
  return (root = local);
}
