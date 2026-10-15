// Local-only, unmounted issuer provisioning. Never print private material.
// Ordinary startup remains disabled pending independent issuer review.
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { openSync, closeSync, fstatSync, readFileSync, writeFileSync, lstatSync,
  unlinkSync, linkSync, fsyncSync, renameSync, constants } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { privateDirectory, provisionLocalHuman } from './issuer_interactions.mjs';
import { CHATGPT_CIMD_ID, CHATGPT_CIMD_REDIRECT } from './issuer_policy.mjs';

const error = () => Error('private issuer setup unavailable');
const idPattern = /^[A-Za-z0-9._~-]{1,128}$/;
const filename = 'issuer.json';
const related = ['issuer.sqlite', 'issuer.sqlite-wal', 'issuer.sqlite-shm', 'issuer.sqlite-journal',
  'interactions.sqlite', 'interactions.sqlite-wal', 'interactions.sqlite-shm', 'interactions.sqlite-journal'];

function readPrivate(path, maxBytes = 200000) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = fstatSync(fd), link = lstatSync(path);
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) ||
        stat.size > maxBytes || stat.dev !== link.dev || stat.ino !== link.ino) throw error();
    return readFileSync(fd, { encoding: 'utf8' });
  } finally { closeSync(fd); }
}

function publicInputs({ origin, clientId, redirectUris, clientRegistration = 'static' }) {
  if (typeof origin !== 'string' || origin.length > 2048 || !/^https:\/\//.test(origin) ||
      new URL(origin).origin !== origin || typeof clientId !== 'string' ||
      !/^[\x21-\x7e]{1,2048}$/.test(clientId) ||
      !Array.isArray(redirectUris) || redirectUris.length !== 1 ||
      redirectUris.some(uri => typeof uri !== 'string' || uri.length > 2048 ||
        !uri.startsWith('https://') || new URL(uri).href !== uri || new URL(uri).hash ||
         new URL(uri).username || new URL(uri).password || new URL(uri).hostname.includes('*')) ||
       !['static', 'chatgpt-cimd'].includes(clientRegistration) ||
       clientRegistration === 'chatgpt-cimd' &&
         (clientId !== CHATGPT_CIMD_ID || redirectUris[0] !== CHATGPT_CIMD_REDIRECT))
    throw Error('exact HTTPS origin/client/redirect required');
  return { origin, clientId, redirectUris, clientRegistration };
}

function freshSigningKey() {
  const privateJwk = generateKeyPairSync('rsa', { modulusLength: 3072 }).privateKey.export({ format: 'jwk' });
  return { ...privateJwk, kid: randomBytes(24).toString('base64url'), alg: 'RS256', use: 'sig' };
}

function writeNewPrivate(directory, name, value) {
  privateDirectory(directory);
  const path = join(directory, name);
  // No overwrites. A temp file in the same private directory is fully written
  // and fsynced before the exclusive final link; failures leave a non-secret
  // error and a manually removable private temp file, never a partial target.
  const temporary = join(directory, `.issuer-setup-${randomBytes(16).toString('hex')}`);
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    writeFileSync(fd, JSON.stringify(value));
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077)) throw error();
    // link(2) is exclusive; rename(2) would overwrite a concurrent setup.
    fsyncSync(fd);
    privateDirectory(directory);
    linkSync(temporary, path);
  } finally { closeSync(fd); unlinkSync(temporary); }
  readPrivate(path);
}

// For tests, a synthetic human.json may be prepared in a disposable directory.
// In production this function only accepts an already TTY-provisioned verifier.
export function finalizeIssuerSetup({ directory, accountId, origin, clientId, redirectUris,
  clientRegistration = 'static' }) {
  publicInputs({ origin, clientId, redirectUris, clientRegistration });
  if (!idPattern.test(accountId)) throw error();
  privateDirectory(directory);
  for (const name of [filename, ...related]) {
    try { lstatSync(join(directory, name)); throw Error('existing issuer state; no overwrite'); }
    catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
  const human = JSON.parse(readPrivate(join(directory, 'human.json'), 4096));
  if (human.accountId !== accountId || typeof human.verifier !== 'string' ||
      !human.verifier.startsWith('$argon2id$')) throw Error('human account mismatch');
  writeNewPrivate(directory, filename, { version: 1, accountId, origin, jwks: { keys: [freshSigningKey()] },
    cookieKeys: [randomBytes(48).toString('base64url')], clientId, redirectUris, clientRegistration });
  return { issuer_mode: 'self-hosted', issuer_state_dir: directory, public_origin: origin,
    issuer: origin, audience: `${origin}/mcp`, principal: accountId, clientId, redirectUris, clientRegistration };
}

export function issuerReferences(directory) {
  privateDirectory(directory);
  const { version, accountId, origin, clientId, redirectUris, clientRegistration = 'static', jwks, cookieKeys } =
    JSON.parse(readPrivate(join(directory, filename)));
  publicInputs({ origin, clientId, redirectUris, clientRegistration });
  const human = JSON.parse(readPrivate(join(directory, 'human.json'), 4096));
  if (version !== 1 || !idPattern.test(accountId) || !Array.isArray(jwks?.keys) ||
      jwks.keys.length !== 1 || !jwks.keys[0].d ||
      jwks.keys[0].alg !== 'RS256' || jwks.keys[0].use !== 'sig' ||
      !jwks.keys[0].kid || jwks.keys[0].kty !== 'RSA' ||
      !Array.isArray(cookieKeys) || cookieKeys.length !== 1 || cookieKeys[0].length < 32 ||
      human.accountId !== accountId || !human.verifier?.startsWith('$argon2id$')) throw error();
  return { issuer_mode: 'self-hosted', issuer_state_dir: directory, public_origin: origin,
    issuer: origin, audience: `${origin}/mcp`, principal: accountId, clientId, redirectUris, clientRegistration };
}

// Pre-start rotation only. Running or previously started issuers have durable
// session/grant/refresh-token state: we cannot prove they are stopped or revoke
// them atomically here. Refuse those states rather than silently preserving them.
export function rotateIssuer({ directory }) {
  issuerReferences(directory);
  privateDirectory(directory);
  for (const name of related) {
    try { lstatSync(join(directory, name)); throw Error('offline issuer rotation requires revoked session state'); }
    catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
  const path = join(directory, filename);
  const previous = JSON.parse(readPrivate(path));
  // The previous private key survives ONLY in the protected rollback backup,
  // never in the active issuer JWKS. Existing signatures cease to verify with
  // the freshly started local verifier; no unbounded old-key grace period.
  const next = { ...previous, jwks: { keys: [freshSigningKey()] },
    cookieKeys: [randomBytes(48).toString('base64url')] };
  delete next.retiredUntil;
  const temp = join(directory, `.issuer-rotate-${randomBytes(16).toString('hex')}`);
  const backup = join(directory, `issuer-backup-${randomBytes(16).toString('hex')}.json`);
  const fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    writeFileSync(fd, JSON.stringify(next)); fsyncSync(fd);
    privateDirectory(directory);
    // Backup is a mode-0600 hard link to the old inode and cannot overwrite.
    linkSync(path, backup);
    renameSync(temp, path);
    const dirFd = openSync(directory, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
  } finally {
    closeSync(fd);
    try { unlinkSync(temp); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
  return { backup };
}

// Rollback: keep the issuer disabled; stop its process before touching state.
// Make a private mode-0600 backup of every existing file first. If init stopped
// after human.json only, remove that newly provisioned verifier offline and
// restart init; if issuer.json exists, do not overwrite it. No automatic key
// or database rollback is safe while any issued credential remains valid.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [verb, directory, origin, clientId, redirect] = process.argv.slice(2);
  if (verb === 'reference' && process.argv.length === 4) {
    try { console.log(JSON.stringify(issuerReferences(directory))); }
    catch { console.error('Private issuer reference unavailable.'); process.exitCode = 1; }
  } else if (verb === 'rotate' && process.argv.length === 4 && process.stdin.isTTY && process.stdout.isTTY) {
    try { rotateIssuer({ directory }); console.log('Offline issuer keys rotated; private backup retained.'); }
    catch { console.error('Offline issuer rotation refused; no active state may be present.'); process.exitCode = 1; }
  } else if (!((verb === 'init' && process.argv.length === 7) ||
      (verb === 'init-chatgpt-cimd' && process.argv.length === 5)) ||
      !process.stdin.isTTY || !process.stdout.isTTY) {
    console.error('Usage: node issuer_setup.mjs reference PRIVATE_DIR; or local TTY: node issuer_setup.mjs init PRIVATE_DIR HTTPS_ORIGIN CLIENT_ID EXACT_HTTPS_REDIRECT; node issuer_setup.mjs init-chatgpt-cimd PRIVATE_DIR HTTPS_ORIGIN; node issuer_setup.mjs rotate PRIVATE_DIR (unused issuer only)');
    process.exitCode = 2;
  } else {
    try {
      const cimd = verb === 'init-chatgpt-cimd';
      const selectedClient = cimd ? CHATGPT_CIMD_ID : clientId;
      const selectedRedirect = cimd ? CHATGPT_CIMD_REDIRECT : redirect;
      const clientRegistration = cimd ? 'chatgpt-cimd' : 'static';
      publicInputs({ origin, clientId: selectedClient, redirectUris: [selectedRedirect], clientRegistration });
      privateDirectory(directory);
      for (const name of ['human.json', filename, ...related]) {
        try { lstatSync(join(directory, name)); throw Error('existing issuer state'); }
        catch (e) { if (e.code !== 'ENOENT') throw e; }
      }
      const accountId = randomBytes(24).toString('base64url');
      await provisionLocalHuman({ directory, accountId });
      finalizeIssuerSetup({ directory, accountId, origin, clientId: selectedClient,
        redirectUris: [selectedRedirect], clientRegistration });
      console.log('Issuer state provisioned privately. Configure the local bridge using issuerReferences; do not publish issuer.json.');
    } catch { console.error('Issuer setup failed; inspect private state offline before retrying.'); process.exitCode = 1; }
  }
}
