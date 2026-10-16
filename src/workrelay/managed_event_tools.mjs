// Lifecycle views/actions over the SAME createEventsService outbox; no second store,
// callback registry or model-visible signing secrets. Shared MCP core owns registration.
const sid = '^ses[A-Za-z0-9_-]{1,160}$', subscriptionID = '^sub_[a-f0-9]{64}$';
const string = { type: 'string' }, nullableTime = { type: ['string', 'null'] };
const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const filter = object({ server_id: { type: 'string', pattern: '^srv_[a-f0-9]{64}$' }, session_id: { type: 'string', pattern: sid } }, ['server_id']);
const subscription = object({ id: { type: 'string', pattern: subscriptionID }, name: string, filter, status: { enum: ['active', 'expired'] }, refresh_before: string,
  queued: { type: 'integer', minimum: 0 }, delivery_state: { enum: ['idle', 'queued', 'in_flight', 'retrying'] }, next_attempt_at: nullableTime,
  delivered: { type: 'integer', minimum: 0 }, dropped: { type: 'integer', minimum: 0 }, last_attempt_at: nullableTime, last_ack_at: nullableTime, last_http_status: { type: ['integer', 'null'] } });
const sessionInput = { session_id: { type: 'string', pattern: sid } };
export const managedEventToolDefinitions = [
  { name: 'workrelay_event_capabilities', description: 'Discover safe Events and receiver prerequisites for the explicitly bound managed server. Subscribe through native MCP2 events/subscribe; never paste a signing secret into tool arguments.', inputSchema: object({}),
    outputSchema: object({ server_id: string, events: { type: 'array', items: { type: 'object' } }, protocol: string, replay: { const: false }, guidance: string }) },
  { name: 'workrelay_event_subscriptions', description: 'List your bound-server subscriptions and delivery counts, without callback URLs, signing keys or event text. Optional session_id matches exact session subscriptions; omission includes server-wide filters.',
    inputSchema: object({ ...sessionInput, limit: { type: 'integer', minimum: 1, maximum: 50 }, cursor: { type: 'string', pattern: subscriptionID } }, []),
    outputSchema: object({ server_id: string, subscriptions: { type: 'array', items: subscription }, next_cursor: { type: ['string', 'null'] } }) },
  { name: 'workrelay_event_subscription_status', description: 'Inspect a subscription ID returned by subscribe/list. HTTP acknowledgement is not proof that ChatGPT processed an event; unknown and inaccessible IDs are indistinguishable.',
    inputSchema: object({ subscription_id: { type: 'string', pattern: subscriptionID }, ...sessionInput }, ['subscription_id']),
    outputSchema: object({ server_id: string, status: { enum: ['available', 'not_found_or_unavailable'] }, subscription: { anyOf: [subscription, { type: 'null' }] } }) },
  { name: 'workrelay_event_unsubscribe', description: 'Idempotently stop only your subscription by ID; queued retries are removed, not the underlying work/service. An already sent webhook cannot be recalled. Retryable revocation_pending is NOT successful revocation.',
    inputSchema: object({ subscription_id: { type: 'string', pattern: subscriptionID }, ...sessionInput }, ['subscription_id']),
    outputSchema: object({ server_id: string, subscription_id: string, status: { const: 'stopped_or_absent' } }) },
].map(definition => ({ ...definition, annotations: { readOnlyHint: definition.name !== 'workrelay_event_unsubscribe', destructiveHint: false, idempotentHint: true, openWorldHint: false } }));

function denied(reason = 'managed_events_denied', code = -32001) { return Object.assign(new Error('Managed Events unavailable or denied'), { code, data: { reason } }); }

/** Core integration contract:
 * createManagedEventTools({events,serverId,identity:{issuer,audience,principal,client_id},authorize})
 * .call(toolName,input,verifiedClaims) -> structured object matching outputSchema.
 * Claims MUST originate from the shared OAuth verifier, NOT input or owner labels.
 * authorize(verifiedClaims,{server_id,session_id?}) MUST reread the capability/revocation
 * boundary and verify the canonical service registration/endpoint. It runs before/after
 * each view/action, including capabilities. A false/failed check never returns data.
 * events is the SAME principal-bound instance used by MCP2 events/* and the scheduler.
 * Core must forward structured errors (especially retryable revocation_pending), and
 * merge descriptors into its catalog/router. No inference, network startup or timers here.
 */
export function createManagedEventTools({ events, serverId, identity, authorize } = {}) {
  if (!events || !/^srv_[a-f0-9]{64}$/.test(serverId) || !identity?.issuer || !identity.audience || !identity.principal || events.principal !== identity.principal || identity.client_id !== 'https://chatgpt.com/oauth/client.json' || typeof authorize !== 'function') throw denied('missing_bound_authority');
  const expected = Object.freeze({ ...identity });
  async function check(claims, scope) {
    if (!claims || claims.iss !== expected.issuer || claims.aud !== expected.audience || claims.sub !== expected.principal || claims.client_id !== expected.client_id) throw denied();
    try { if (await authorize(claims, scope) !== true) throw denied(); } catch { throw denied(); }
  }
  return {
    definitions: structuredClone(managedEventToolDefinitions),
    async call(name, input, claims) {
      const definition = managedEventToolDefinitions.find(d => d.name === name);
      if (!definition || !input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(k => !Object.hasOwn(definition.inputSchema.properties, k)) || definition.inputSchema.required.some(k => !Object.hasOwn(input, k))) throw denied('invalid_arguments', -32602);
      if (input.session_id !== undefined && (typeof input.session_id !== 'string' || !new RegExp(sid).test(input.session_id)) || input.subscription_id !== undefined && (typeof input.subscription_id !== 'string' || !new RegExp(subscriptionID).test(input.subscription_id)) || input.limit !== undefined && (!Number.isInteger(input.limit) || input.limit < 1 || input.limit > 50) || input.cursor !== undefined && (typeof input.cursor !== 'string' || !new RegExp(subscriptionID).test(input.cursor))) throw denied('invalid_arguments', -32602);
      const scope = { server_id: serverId, ...(input.session_id ? { session_id: input.session_id } : {}) };
      await check(claims, scope);
      let result;
      if (name === 'workrelay_event_capabilities') result = { server_id: serverId, events: (await events.list()).events.filter(e => e.name.startsWith('session.')), protocol: 'MCP2 2026-07-28 webhook', replay: false,
        guidance: 'Ask ChatGPT in a Work chat/Cloud or Dot to subscribe through native events/subscribe with server_id and optional session_id. ChatGPT supplies and verifies its HTTPS callback/signing key. Polling reconciles observed state, not missed history. Progress reflects explicit runtime-state transitions; idle is not task completion. HTTP acknowledgement is not receiver task completion.' };
      else if (name === 'workrelay_event_subscriptions') result = { server_id: serverId, ...await events.subscriptions({ filter: scope, limit: input.limit, cursor: input.cursor }) };
      else if (name === 'workrelay_event_subscription_status') { const status = await events.subscriptionStatus({ id: input.subscription_id, filter: scope }); result = { server_id: serverId, status: status.subscription ? 'available' : 'not_found_or_unavailable', ...status }; }
      else result = { server_id: serverId, ...await events.unsubscribeById({ id: input.subscription_id, filter: scope }) };
      await check(claims, scope);
      return result;
    },
  };
}
