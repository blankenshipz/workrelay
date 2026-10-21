// oidc-provider's documented adapter interface, backed by private SQLite IPC.
// This is storage infrastructure, NOT an enabled authorization server.
import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { errors } from 'oidc-provider';

export function createIssuerAdapter(stateDir, python = '/usr/bin/python3') {
  if (typeof stateDir !== 'string' || !stateDir.startsWith('/') || typeof python !== 'string')
    throw new Error('private issuer state required');
  const source = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  function call(command) {
    let input;
    try { input = JSON.stringify(command); }
    catch { return Promise.reject(new Error('private issuer storage unavailable')); }
    if (typeof input !== 'string' || Buffer.byteLength(input, 'utf8') > 300000)
      return Promise.reject(new Error('private issuer storage unavailable'));
    return new Promise((done, reject) => {
      const child = spawn(python, ['-m', 'workrelay.oidc_store', stateDir], {
        env: { PATH: '/usr/bin:/bin', PYTHONPATH: source }, stdio: ['pipe', 'pipe', 'pipe'],
      });
      let output = '';
      const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
      child.stdout.on('data', chunk => { output += chunk; if (output.length > 300000) child.kill('SIGKILL'); });
      child.stderr.resume(); // never log private storage errors or payloads
      child.on('error', () => { clearTimeout(timer); reject(new Error('private issuer storage unavailable')); });
      child.on('close', code => {
        clearTimeout(timer);
        if (code !== 0) return reject(new Error('private issuer storage unavailable'));
        try { done(JSON.parse(output)); }
        catch { reject(new Error('private issuer storage unavailable')); }
      });
      child.stdin.on('error', () => {}); // EPIPE surfaces as nonzero child status
      child.stdin.end(input); // no token, subject, payload, or secret in argv
    });
  }
  return class PrivateIssuerAdapter {
    constructor(model) { this.model = model; }
    upsert(id, payload, expiresIn) { return call({ model: this.model, action: 'upsert', id, payload, expiresIn }); }
    find(id) { return call({ model: this.model, action: 'find', id }); }
    findByUid(id) { return call({ model: this.model, action: 'findByUid', id }); }
    findByUserCode(id) { return call({ model: this.model, action: 'findByUserCode', id }); }
    async consume(id) {
      const result = await call({ model: this.model, action: 'consume', id });
      if (this.model === 'RefreshToken' && result?.error === 'refresh_token_unavailable')
        throw new errors.InvalidGrant('refresh token no longer available');
      return result;
    }
    destroy(id) { return call({ model: this.model, action: 'destroy', id }); }
    revokeByGrantId(grantId) { return call({ model: this.model, action: 'revokeByGrantId', grantId }); }
  };
}
