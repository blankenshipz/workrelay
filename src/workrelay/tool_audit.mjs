// Structured audit log of gateway MCP tool calls: one JSON line per call.
//
// Records ONLY: timestamp, tool name, session ID, operation key, OAuth client ID,
// duration and a closed status/error category. Never message text, prompts,
// answers, other tool arguments, tool output, tokens, secrets or exception text.
// Every identifier is re-validated against a fixed pattern before it is written.
// Writing is best effort: an audit failure never changes or fails the tool call.
import { openSync, closeSync, fstatSync, writeSync, renameSync, unlinkSync, constants } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { privateDirectory } from './issuer_interactions.mjs';

export const AUDIT_DEFAULT_FILE = 'tool-audit.jsonl';
export const AUDIT_DEFAULT_MAX_BYTES = 10 * 1024 * 1024;
export const AUDIT_DEFAULT_MAX_FILES = 3;
const SESSION = /^ses[A-Za-z0-9_-]{1,160}$/;
const OPERATION = /^[A-Za-z0-9_-]{1,80}$/;
const CLIENT = /^[\x21-\x7e]{1,2048}$/;
const TOOL = /^workrelay_[a-z_]{1,64}$/;
const CONTROL_CATEGORIES = {
  CONTROL_AUTHORIZATION_OR_VALIDATION_DENIED: 'denied', CONTROL_NOT_SENT: 'denied',
  CONTROL_UNCERTAIN: 'uncertain', CONTROL_RECONCILE_EXISTING: 'conflict',
  CONTROL_OPERATION_NOT_FOUND_CURRENT_BINDING: 'not_found', CONTROL_OPERATION_AMBIGUOUS_CURRENT_BINDING: 'ambiguous',
};

// Returns null (disabled) or exact settings. `audit_log` is optional:
// omitted -> <issuer_state_dir>/tool-audit.jsonl when a private issuer state
// directory exists, else disabled; false -> disabled; object -> explicit.
export function auditSettings(config) {
  const value = config.audit_log;
  if (value === false) return null;
  if (value !== undefined && (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !['path', 'max_bytes', 'max_files'].includes(key))))
    throw Error('audit log requires an absolute private path and bounded rotation');
  const path = value?.path ?? (typeof config.issuer_state_dir === 'string' ? join(config.issuer_state_dir, AUDIT_DEFAULT_FILE) : undefined);
  if (path === undefined && value === undefined) return null;
  const maxBytes = value?.max_bytes ?? AUDIT_DEFAULT_MAX_BYTES, maxFiles = value?.max_files ?? AUDIT_DEFAULT_MAX_FILES;
  if (typeof path !== 'string' || !path.startsWith('/') || resolve(path) !== path || path.endsWith('/') ||
      !Number.isSafeInteger(maxBytes) || maxBytes < 4096 || maxBytes > 1024 ** 3 ||
      !Number.isSafeInteger(maxFiles) || maxFiles < 1 || maxFiles > 20)
    throw Error('audit log requires an absolute private path and bounded rotation');
  return { path, maxBytes, maxFiles };
}

const pick = (pattern, ...values) => values.find(value => typeof value === 'string' && pattern.test(value)) ?? null;

// Closed outcome classification from the tool result's structured fields only.
export function auditOutcome(result, thrown, { denialCodes = [], checkIds = [] } = {}) {
  if (thrown) return { status: 'error', error_category: 'exception' };
  const out = result?.structuredContent;
  const denied = out?.phase === 'denied' || out?.recorded_phase === 'denied';
  if (result?.isError !== true && !denied) return { status: 'ok' };
  const code = typeof out?.code === 'string' && Object.hasOwn(CONTROL_CATEGORIES, out.code) ? out.code : null;
  const entry = { status: 'error', error_category: code ? CONTROL_CATEGORIES[code] : denied ? 'denied' :
    out?.error && typeof out.error === 'object' ? 'events_denied' : out ? 'tool_error' : 'unavailable_or_denied' };
  if (code) entry.error_code = code;
  if (denialCodes.includes(out?.denial_code)) entry.denial_code = out.denial_code;
  if (entry.denial_code === 'ATTESTATION_FAILED' && checkIds.includes(out?.attestation_check_id)) entry.attestation_check_id = out.attestation_check_id;
  return entry;
}

export function auditEntry({ tool, input, ctx, result, thrown, durationMs, now = Date.now, codes } = {}) {
  const out = result?.structuredContent;
  return {
    ts: new Date(now()).toISOString(),
    tool: pick(TOOL, tool),
    session_id: pick(SESSION, input?.session_id, out?.session_id),
    operation_key: pick(OPERATION, input?.operation_id, input?.key),
    client_id: pick(CLIENT, ctx?.http?.authInfo?.extra?.managedClaims?.client_id),
    duration_ms: Number.isFinite(durationMs) && durationMs >= 0 ? Math.round(durationMs) : null,
    ...auditOutcome(result, thrown, codes),
  };
}

export function createToolAudit({ path, maxBytes = AUDIT_DEFAULT_MAX_BYTES, maxFiles = AUDIT_DEFAULT_MAX_FILES, now = Date.now, codes } = {}) {
  const safe = info => info.isFile() && info.uid === process.getuid() && (info.mode & 0o077) === 0 && info.nlink === 1;
  const open = () => openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);
  function rotate() {
    // path -> path.1 -> ... -> path.<maxFiles>; the oldest is replaced. Total
    // retained size is bounded by (maxFiles + 1) * maxBytes.
    try { unlinkSync(`${path}.${maxFiles}`); } catch { /* absent */ }
    for (let index = maxFiles - 1; index >= 1; index--) {
      try { renameSync(`${path}.${index}`, `${path}.${index + 1}`); } catch { /* absent */ }
    }
    renameSync(path, `${path}.1`);
  }
  function write(line) {
    let fd;
    try {
      privateDirectory(dirname(path));
      fd = open();
      let info = fstatSync(fd);
      if (!safe(info)) return false;
      if (info.size > 0 && info.size + Buffer.byteLength(line) > maxBytes) {
        closeSync(fd); fd = undefined;
        rotate();
        fd = open(); info = fstatSync(fd);
        if (!safe(info)) return false;
      }
      writeSync(fd, line);
      return true;
    } catch { return false; } finally {
      if (fd !== undefined) try { closeSync(fd); } catch { /* ignored */ }
    }
  }
  const audit = {
    path,
    record(details) {
      try { return write(JSON.stringify(auditEntry({ ...details, now, codes })) + '\n'); }
      catch { return false; }
    },
    // Wrap one tool handler; the audit record never alters its result or error.
    wrap(tool, handler) {
      return async (input, ctx) => {
        const started = performance.now();
        let result, thrown = false;
        try { result = await handler(input, ctx); return result; }
        catch (error) { thrown = true; throw error; }
        finally { audit.record({ tool, input, ctx, result, thrown, durationMs: performance.now() - started }); }
      };
    },
  };
  return audit;
}
