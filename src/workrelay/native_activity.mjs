// Project only finite execution facts from an already validated native message
// page.  This is deliberately not a live-state model: a running tool on an
// older page is historical evidence only.
const toolID = /^[A-Za-z0-9_-]{1,160}$/;
const knownTools = new Set(['edit', 'glob', 'grep', 'list', 'read', 'shell', 'task', 'webfetch', 'websearch', 'write']);
const knownStatuses = new Set(['pending', 'running', 'completed', 'failed', 'error', 'cancelled', 'timeout']);

function timestamp(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 8640000000000000 ? value : undefined;
}

function toolName(value) {
  return typeof value === 'string' && knownTools.has(value) ? value : 'other';
}

function status(value) {
  return typeof value === 'string' && knownStatuses.has(value) ? value : 'unknown';
}

// Raw tool parts often contain command/input/output/reasoning/provider data.
// Never spread either the part or its state: this closed projection is the
// public contract.
function activityPart(part, messageID, messageTime) {
  if (!part || part.type !== 'tool' || !toolID.test(part.id ?? '')) return null;
  const state = part.state && typeof part.state === 'object' && !Array.isArray(part.state) ? part.state : {};
  const time = state.time && typeof state.time === 'object' && !Array.isArray(state.time) ? state.time : {};
  const metadata = state.metadata && typeof state.metadata === 'object' && !Array.isArray(state.metadata) ? state.metadata : {};
  const messageCreatedAt = timestamp(messageTime?.created);
  const messageCompletedAt = timestamp(messageTime?.completed);
  const createdAt = timestamp(time.created);
  const ranAt = timestamp(time.ran);
  const completedAt = timestamp(time.completed);
  const exitCode = Number.isSafeInteger(metadata.exit) ? metadata.exit : undefined;
  const timedOut = metadata.timeout === true;
  return {
    message_id: messageID,
    tool_id: part.id,
    tool: toolName(part.tool ?? part.name),
    status: status(state.status),
    ...(messageCreatedAt === undefined ? {} : { message_created_at: messageCreatedAt }),
    ...(messageCompletedAt === undefined ? {} : { message_completed_at: messageCompletedAt }),
    ...(createdAt === undefined ? {} : { created_at: createdAt }),
    ...(ranAt === undefined ? {} : { ran_at: ranAt }),
    ...(completedAt === undefined ? {} : { completed_at: completedAt }),
    ...(exitCode === undefined ? {} : { exit_code: exitCode }),
    ...(timedOut ? { timed_out: true } : {}),
  };
}

export function nativeActivity(messages) {
  const items = []; let truncated = false;
  outer:
  for (const message of messages) {
    if (!message || message.type !== 'assistant' || !toolID.test(message.id ?? '') || !Array.isArray(message.content)) continue;
    for (const part of message.content) {
      const item = activityPart(part, message.id, message.time);
      if (!item) continue;
      if (items.length === 20) { truncated = true; break outer; }
      items.push(item);
    }
  }
  return {
    scope: 'this_page_only',
    temporal_scope: 'historical_message_page',
    current_state: 'unknown',
    items,
    truncated,
    limitation: 'Historical tool observations from this fetched message page only. A running status is not evidence that a tool is currently running; completion is not verified task progress.',
  };
}
