// Native V2 SSE is a volatile wake-up source, not a replayable event ledger.
// Durable observations/outbox remain owned by createEventsService. Never forward
// native payloads (which may contain transcripts, tool input or hidden reasoning).
const validServer = value => /^srv_[a-f0-9]{64}$/.test(value);
const validSession = value => typeof value === 'string' && /^ses[A-Za-z0-9_-]{1,160}$/.test(value);
const changed = new Set(['session.created', 'session.updated', 'session.deleted', 'session.idle', 'session.status', 'session.error', 'permission.asked', 'permission.created', 'permission.updated', 'permission.replied', 'session.permission.created', 'session.permission.updated']);
for (const kind of ['session.execution.started', 'session.execution.succeeded', 'session.execution.failed', 'session.execution.interrupted', 'session.inbox.enqueued', 'session.inbox.delivered', 'session.retry.scheduled']) changed.add(kind);
const error = reason => Object.assign(new Error('Managed event source unavailable'), { code: -32000, data: { reason } });

/** openStream({signal}) -> {server_id,response}: a trusted adapter must perform
 * Service.discover + exact canonical binding/registration checks and authenticated
 * GET /api/event, redirect:error/manual. It must never ensure/start another service.
 * authorize() rereads the same pinned principal/server capability; true required.
 * reconcile() calls existing pollManaged/deliverDue, both of which recheck grants.
 * isSubscribed(sessionID) scopes native wakes; no raw payload leaves this module.
 * On connect and completion reconcile current state. No Last-Event-ID is sent and
 * native SSE IDs are not advertised as replay cursors. Caller owns reconnect timer
 * and shutdown. A bounded attempt never shuts down OpenCode or ordinary work.
 */
export function createManagedEventSource({ serverId, openStream, authorize, reconcile, onNativeEvent, isSubscribed = () => false, maxFrameBytes = 262144, maxStreamBytes = 2097152, maxFrames = 256 } = {}) {
  if (!validServer(serverId) || [openStream, authorize, reconcile, isSubscribed].some(fn => typeof fn !== 'function')) throw error('missing_bound_source');
  async function admitted() { try { if (await authorize() === true) return; } catch {} throw error('source_authority_revoked'); }
  return {
    async consume({ signal, durationMs = 10000 } = {}) {
      if (!Number.isInteger(durationMs) || durationMs < 10 || durationMs > 60000) throw error('invalid_source_bounds');
      const controller = new AbortController(), abort = () => controller.abort();
      const timer = setTimeout(abort, durationMs); signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
      let reader; controller.signal.addEventListener('abort', () => { void reader?.cancel().catch(() => {}); }, { once: true });
      const result = { connected: false, frames: 0, native_events: 0, scoped_wakes: 0, session_hints: 0, native_kinds: {}, reconciliations: 0, replay: false, ended: 'eof' };
      const sync = async () => { await admitted(); await reconcile(); result.reconciliations++; };
      try {
        await admitted(); if (controller.signal.aborted) throw error('source_aborted');
        const opened = await openStream({ signal: controller.signal });
        if (opened?.server_id !== serverId || opened.response?.status !== 200 || !opened.response.headers.get('content-type')?.toLowerCase().startsWith('text/event-stream') || opened.response.redirected) { await opened?.response?.body?.cancel(); throw error('invalid_native_stream'); }
        result.connected = true; await sync(); reader = opened.response.body.getReader();
        const decoder = new TextDecoder('utf-8', { fatal: true }); let pending = '', bytes = 0;
        async function frame(text) {
          if (Buffer.byteLength(text) > maxFrameBytes) throw error('source_frame_too_large');
          const data = text.split('\n').filter(line => line.startsWith('data:')).map(line => line.slice(5).replace(/^ /, '')).join('\n');
          if (!data) return; result.frames++; if (result.frames > maxFrames) throw error('source_backpressure');
          let value; try { value = JSON.parse(data); if (typeof value === 'string') value = JSON.parse(value); } catch { throw error('invalid_native_event'); }
          if (!value || typeof value !== 'object') throw error('invalid_native_event');
          result.native_events++; await admitted();
          const type = value.type ?? value.event?.type;
          const payload = value.data ?? value.properties ?? value.payload ?? value.event?.properties;
          const session = payload?.sessionID ?? payload?.sessionId ?? payload?.session?.id ?? payload?.info?.id ?? (type?.startsWith('session.') ? payload?.id : undefined);
          const label = changed.has(type) || type === 'server.connected' ? type : 'other';
          result.native_kinds[label] = (result.native_kinds[label] ?? 0) + 1;
          if (validSession(session)) result.session_hints++;
          if (changed.has(type) && validSession(session) && await isSubscribed(session)) {
            if (onNativeEvent) {
              if (!/^evt_[A-Za-z0-9_-]{1,150}$/.test(value.id) || !Number.isFinite(value.created)) throw error('invalid_native_event');
              await onNativeEvent({ server_id: serverId, session_id: session, kind: type, event_id: value.id, created: value.created });
            }
            await sync(); result.scoped_wakes++;
          }
        }
        while (!controller.signal.aborted) {
          const part = await reader.read(); if (part.done) break;
          bytes += part.value.byteLength; if (bytes > maxStreamBytes) throw error('source_backpressure');
          pending += decoder.decode(part.value, { stream: true }); pending = pending.replace(/\r\n/g, '\n');
          let separator; while ((separator = pending.indexOf('\n\n')) >= 0) { const complete = pending.slice(0, separator); pending = pending.slice(separator + 2); await frame(complete); }
          if (Buffer.byteLength(pending) > maxFrameBytes) throw error('source_frame_too_large');
        }
        if (controller.signal.aborted) result.ended = 'bounded_stop';
      } catch (cause) {
        if (controller.signal.aborted) result.ended = 'bounded_stop';
        else { const failure = cause?.data?.reason ? cause : error('native_stream_failed'); failure.sourceEvidence = { ...result }; throw failure; }
      } finally {
        controller.abort(); clearTimeout(timer); signal?.removeEventListener('abort', abort);
        try { await reader?.cancel(); } catch {}
      }
      if (result.connected && !signal?.aborted) await sync();
      return result;
    },
  };
}
