// Optional operator notification for NEW pending native permission requests.
// Fire-and-forget: never awaited by tool calls, never throws, never approves.
// Payload is a fixed set of non-secret summary fields; command/resource text
// from the native request is deliberately excluded.
import { spawn } from 'node:child_process';

export function validateNotifySettings(value) {
  if (value === undefined) return;
  const ok = value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).every(key => ['enabled', 'directories', 'notify_command', 'notify_webhook_url', 'poll_interval_ms', 'local_listen'].includes(key)) &&
    value.enabled === true &&
    (value.directories === undefined || Array.isArray(value.directories) && value.directories.length >= 1 && value.directories.length <= 100 &&
      value.directories.every(dir => typeof dir === 'string' && dir.startsWith('/') && dir !== '/' && !dir.endsWith('/') && !dir.split('/').some(part => part === '.' || part === '..'))) &&
    (value.notify_command === undefined || Array.isArray(value.notify_command) && value.notify_command.length >= 1 && value.notify_command.length <= 32 &&
      value.notify_command.every(arg => typeof arg === 'string' && arg.length <= 4096 && !/[\x00]/.test(arg)) && value.notify_command[0].startsWith('/')) &&
    (value.poll_interval_ms === undefined || Number.isSafeInteger(value.poll_interval_ms) && value.poll_interval_ms >= 5000 && value.poll_interval_ms <= 3600000) &&
    // Optional loopback-only operator page listener: exactly { port }, off by default.
    (value.local_listen === undefined || value.local_listen !== null && typeof value.local_listen === 'object' && !Array.isArray(value.local_listen) &&
      Object.keys(value.local_listen).length === 1 && Number.isSafeInteger(value.local_listen.port) &&
      value.local_listen.port >= 1024 && value.local_listen.port <= 65535);
  if (!ok) throw Error('invalid operator_approvals configuration');
  if (value.notify_webhook_url !== undefined) {
    let url;
    try { url = new URL(value.notify_webhook_url); } catch { throw Error('invalid operator_approvals configuration'); }
    if (!(url.protocol === 'https:' || url.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname)) || url.username || url.password)
      throw Error('invalid operator_approvals configuration');
  }
}

export function createPermissionNotifier({ command, webhookUrl, approvalUrl, spawnImpl = spawn, fetchImpl = fetch, maxTracked = 5000 } = {}) {
  if (!command && !webhookUrl) return null;
  const notified = new Set();
  return function notify(items) {
    for (const item of Array.isArray(items) ? items : []) {
      try {
        if (typeof item?.permission_id !== 'string' || notified.has(item.permission_id)) continue;
        notified.add(item.permission_id);
        if (notified.size > maxTracked) notified.delete(notified.values().next().value);
        const payload = JSON.stringify({ event: 'workrelay.permission.pending', permission_id: item.permission_id,
          session_id: item.session_id, action: item.action, first_seen_at: item.first_seen_at,
          ...(approvalUrl ? { approval_url: approvalUrl } : {}),
          guidance: 'A human operator must approve or deny this request; the requesting agent cannot.' });
        if (command) {
          const child = spawnImpl(command[0], command.slice(1), { stdio: ['pipe', 'ignore', 'ignore'], env: { PATH: '/usr/bin:/bin' }, timeout: 10000 });
          child.on?.('error', () => {}); child.stdin?.on?.('error', () => {});
          child.stdin?.end(payload);
        }
        if (webhookUrl) {
          Promise.resolve().then(() => fetchImpl(webhookUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: payload,
            redirect: 'error', signal: AbortSignal.timeout(5000) })).then(response => response?.body?.cancel?.()).catch(() => {});
        }
      } catch { /* notification failure never affects reads or approvals */ }
    }
  };
}
