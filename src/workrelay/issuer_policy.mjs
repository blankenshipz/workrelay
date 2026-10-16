// Unmounted policy prototype for the maintained oidc-provider. Never route
// requests here until private provisioning, login, consent and CSRF are ready.
import Provider, { errors } from 'oidc-provider';
import { openSync, closeSync, fstatSync, lstatSync, readFileSync, writeFileSync,
  linkSync, unlinkSync, fsyncSync, constants } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { privateDirectory } from './issuer_interactions.mjs';

const preapprovalReasons = new Set(['account', 'session', 'client', 'redirect',
  'resource_absent', 'resource_array', 'resource_other', 'scope_absent', 'scope_other', 'response_type']);

// Same exclusive private arm/used/receipt protocol as the interaction recorder.
// A separate target prevents a login/consent recorder from consuming this arm.
export function createPreapprovalDiagnostic(directory) {
  return reason => {
    let fd, temporary;
    try {
      if (!preapprovalReasons.has(reason)) return;
      privateDirectory(directory);
      const arm = join(directory, 'origin-post.arm'), used = join(directory, 'origin-post.used');
      const receipt = join(directory, 'origin-post.receipt.json');
      fd = openSync(arm, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const info = fstatSync(fd), pathInfo = lstatSync(arm);
      if (!info.isFile() || info.uid !== process.getuid() || info.mode & 0o077 || info.nlink !== 1 ||
          info.size > 160 || info.dev !== pathInfo.dev || info.ino !== pathInfo.ino) return;
      const { target, attemptId, expiresAt } = JSON.parse(readFileSync(fd, 'utf8'));
      closeSync(fd); fd = undefined;
      if (target !== 'preapproval' || !/^[a-f0-9]{32}$/.test(attemptId ?? '') ||
          !Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() || expiresAt > Date.now() + 120000) return;
      try { lstatSync(receipt); return; } catch (error) { if (error.code !== 'ENOENT') return; }
      linkSync(arm, used);
      unlinkSync(arm);
      temporary = join(directory, `origin-post.${randomBytes(16).toString('hex')}.tmp`);
      fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      writeFileSync(fd, JSON.stringify({ attemptId, stage: 'preapproval', rejectionClass: reason }));
      fsyncSync(fd); closeSync(fd); fd = undefined;
      linkSync(temporary, receipt);
      fd = openSync(directory, constants.O_RDONLY | constants.O_NOFOLLOW); fsyncSync(fd);
    } catch { /* Recording cannot affect authorization or disclose an error. */ }
    finally {
      if (fd !== undefined) try { closeSync(fd); } catch { /* ignored */ }
      if (temporary) try { unlinkSync(temporary); } catch { /* ignored */ }
    }
  };
}

export const CHATGPT_CIMD_ID = 'https://chatgpt.com/oauth/client.json';
export const CHATGPT_CIMD_REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect';

export async function restrictedClientDocument(url, options, fetchDocument = globalThis.fetch) {
  // The maintained provider supplies a dispatcher that rejects special-use
  // resolved IPs at socket connect (including after DNS changes). Never fall
  // back to an unchecked fetch in the production path.
  if (url !== CHATGPT_CIMD_ID || options.redirect !== 'manual' ||
      (fetchDocument === globalThis.fetch && !options.dispatcher)) throw Error('client document fetch denied');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 2500);
  const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
  try {
  const abort = () => { throw Error('client document timed out'); };
  const within = async promise => {
    if (signal.aborted) abort();
    let rejectTimeout;
    const timeout = new Promise((_, reject) => { rejectTimeout = reject; });
    const onAbort = () => rejectTimeout(Error('client document timed out'));
    signal.addEventListener('abort', onAbort, { once: true });
    try { return await Promise.race([promise, timeout]); }
    finally { signal.removeEventListener('abort', onAbort); }
  };
  const response = await within(fetchDocument(url, { ...options, signal }));
  if (signal.aborted) abort();
  if (response.status !== 200 || response.redirected ||
      (fetchDocument === globalThis.fetch && response.url !== CHATGPT_CIMD_ID) ||
      (response.url && response.url !== CHATGPT_CIMD_ID) ||
      !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('content-type') ?? '') ||
      (response.headers.has('content-length') &&
        (!/^\d+$/.test(response.headers.get('content-length')) || Number(response.headers.get('content-length')) > 8192)))
    throw Error('client document response denied');
  if (!response.body) throw Error('client document empty');
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await within(reader.read());
      if (done) break;
      size += value.byteLength;
      if (size > 8192) throw Error('client document too large');
      chunks.push(value);
    }
  } catch (error) { void reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
  if (signal.aborted) abort();
  const doc = JSON.parse(Buffer.concat(chunks, size).toString('utf8'));
  if (doc.client_id !== CHATGPT_CIMD_ID ||
      !Array.isArray(doc.redirect_uris) || doc.redirect_uris.length !== 1 ||
      doc.redirect_uris[0] !== CHATGPT_CIMD_REDIRECT ||
      !Array.isArray(doc.token_endpoint_auth_methods_supported) ||
      !doc.token_endpoint_auth_methods_supported.includes('none') ||
      !['none', 'private_key_jwt'].includes(doc.token_endpoint_auth_method) ||
      !Array.isArray(doc.grant_types) || !doc.grant_types.includes('authorization_code') ||
      !Array.isArray(doc.response_types) || !doc.response_types.includes('code') ||
      'client_secret' in doc || 'jwks' in doc ||
      doc.jwks_uri !== undefined && doc.jwks_uri !== 'https://chatgpt.com/oauth/jwks.json' ||
      ['sector_identifier_uri', 'request_uris', 'initiate_login_uri', 'backchannel_logout_uri',
        'frontchannel_logout_uri', 'authorization_endpoint', 'token_endpoint'].some(field => field in doc))
    throw Error('client document metadata denied');
  // ChatGPT's transitional legacy singular preference is private_key_jwt;
  // select its explicitly published `none` method from the plural set. The
  // issuer only accepts public PKCE clients; no remote signing keys are used.
  return new Response(JSON.stringify({ client_id: CHATGPT_CIMD_ID,
    redirect_uris: [CHATGPT_CIMD_REDIRECT], token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] }),
    { status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'max-age=30' } });
  } finally { clearTimeout(timer); }
}

const exactHttps = (value, allowOrigin = false) => {
  if (typeof value !== 'string' || value.length > 2048) throw Error('invalid issuer policy');
  const uri = new URL(value);
  if (uri.protocol !== 'https:' || uri.username || uri.password || uri.hash ||
      (uri.href !== value && !(allowOrigin && uri.origin === value)) || uri.hostname.includes('*')) throw Error('invalid issuer policy');
  return uri;
};

// RFC8707/provider parameters may retain repeated resource indicators as an
// array. Accept only a bounded repetition of the one locally approved target,
// never a distinct additional audience or a missing/empty resource.
function exactResource(value, resource) {
  if (value === resource) return true;
  if (!Array.isArray(value) || value.length < 1 || value.length > 8) return false;
  for (let index = 0; index < value.length; index++) {
    if (!Object.hasOwn(value, index) || typeof value[index] !== 'string' || value[index] !== resource) return false;
  }
  return true;
}

export async function loadPreapprovedChatGPTGrant(ctx, { principal, resource, onDenied }) {
  const { account, session, client, params, provider } = ctx.oidc;
  const reason = account?.accountId !== principal ? 'account' : session?.accountId !== principal ? 'session' :
    client?.clientId !== CHATGPT_CIMD_ID || params.client_id !== CHATGPT_CIMD_ID ? 'client' :
    params.redirect_uri !== CHATGPT_CIMD_REDIRECT ? 'redirect' :
    !exactResource(params.resource, resource) ? (params.resource === undefined ? 'resource_absent' :
      Array.isArray(params.resource) ? 'resource_array' : 'resource_other') :
    params.scope !== 'workrelay:tasks' ? (params.scope ? 'scope_other' : 'scope_absent') :
    params.response_type !== 'code' ? 'response_type' : null;
  if (reason) {
    try { onDenied?.(reason); } catch { /* never change the denial */ }
    throw new errors.AccessDenied('request outside locally preapproved grant');
  }
  const grantId = ctx.oidc.result?.consent?.grantId || session.grantIdFor(client.clientId);
  if (grantId) {
    const existing = await provider.Grant.find(grantId);
    if (!existing || existing.accountId !== principal || existing.clientId !== client.clientId)
      throw new errors.AccessDenied('existing grant unavailable');
    return existing; // Never recreate a revoked session-bound grant.
  }
  const grant = new provider.Grant({ accountId: principal, clientId: CHATGPT_CIMD_ID });
  grant.addResourceScope(resource, 'workrelay:tasks');
  await grant.save();
  return grant;
}

export function createUnexposedIssuerPolicy({ origin, principal, jwks, cookieKeys, clientId,
  redirectUris, adapter, findAccount, clientRegistration = 'static', fetchClientDocument, preapproveChatGPT = false,
  onPreapprovalDenied }) {
  const issuer = exactHttps(origin, true);
  if (issuer.pathname !== '/' || issuer.search || !principal || typeof principal !== 'string' ||
      !Array.isArray(jwks?.keys) || !jwks.keys.length ||
      !Array.isArray(cookieKeys) || !cookieKeys.length || cookieKeys.some(key => typeof key !== 'string' || key.length < 32) ||
      typeof clientId !== 'string' || !clientId || !Array.isArray(redirectUris) || !redirectUris.length ||
      typeof adapter !== 'function' || typeof findAccount !== 'function') throw Error('invalid issuer policy');
  const allowed = redirectUris.map(uri => exactHttps(uri).href);
  if (new Set(allowed).size !== allowed.length) throw Error('invalid issuer policy');
  const cimd = clientRegistration === 'chatgpt-cimd';
  if (!['static', 'chatgpt-cimd'].includes(clientRegistration) ||
      cimd && (clientId !== CHATGPT_CIMD_ID || allowed.length !== 1 ||
        allowed[0] !== CHATGPT_CIMD_REDIRECT)) throw Error('invalid issuer policy');
  const resource = `${issuer.origin}/mcp`;
  if (typeof preapproveChatGPT !== 'boolean' || preapproveChatGPT && !cimd)
    throw Error('preapproval requires exact ChatGPT CIMD policy');
  return new Provider(issuer.origin, {
    ...(preapproveChatGPT ? { loadExistingGrant: ctx => {
      // Supported provider hook, called only after loadAccount. Never invent an
      // authenticated session or expand the single locally approved capability.
      return loadPreapprovedChatGPTGrant(ctx, { principal, resource, onDenied: onPreapprovalDenied });
    } } : {}),
    clientAuthMethods: ['none'],
    ...(cimd ? { fetch: (url, options) => restrictedClientDocument(url, options, fetchClientDocument) } : {}),
    adapter, jwks, cookies: { keys: cookieKeys, long: { httpOnly: true, secure: true, sameSite: 'lax' },
      short: { httpOnly: true, secure: true, sameSite: 'lax' } },
    clients: cimd ? [] : [{ client_id: clientId, redirect_uris: allowed,
      token_endpoint_auth_method: 'none', response_types: ['code'],
      grant_types: ['authorization_code', 'refresh_token'] }],
    findAccount: async (ctx, accountId, source) => {
      if (accountId !== principal) return undefined;
      const account = await findAccount(ctx, accountId, source);
      if (account?.accountId !== principal) return undefined;
      return account;
    },
    // Invoked by oidc-provider before saving any access token, including a
    // rotated refresh grant. Never let a code inherit its authorized resource
    // when this token request omitted the RFC 8707 resource parameter.
    extraTokenClaims: async (ctx, token) => {
      if (ctx.oidc.route !== 'token' || !exactResource(ctx.oidc.params.resource, resource) ||
          token.accountId !== principal || ctx.oidc.client?.clientId !== clientId)
        throw new errors.InvalidTarget();
      return undefined;
    },
    pkce: { required: () => true },
    rotateRefreshToken: () => true,
    issueRefreshToken: (_ctx, client) => client.grantTypeAllowed('refresh_token'),
    features: {
      devInteractions: { enabled: false },
      registration: { enabled: false },
      clientIdMetadataDocument: cimd ? { enabled: true, ack: 'draft-02',
        allowFetch: async (_ctx, id) => id === CHATGPT_CIMD_ID,
        allowClient: async (_ctx, client) => client.clientId === CHATGPT_CIMD_ID &&
          client.tokenEndpointAuthMethod === 'none' &&
          client.redirectUris?.length === 1 && client.redirectUris[0] === CHATGPT_CIMD_REDIRECT } : { enabled: false },
      revocation: { enabled: true },
      resourceIndicators: { enabled: true,
        defaultResource: async () => { throw new errors.InvalidTarget(); },
        getResourceServerInfo: async (_ctx, target, client) => {
          if (target !== resource || client.clientId !== clientId) throw new errors.InvalidTarget();
          return { scope: 'workrelay:tasks', audience: resource, accessTokenTTL: 300,
            accessTokenFormat: 'jwt', jwt: { sign: { alg: 'RS256' } } };
        } },
    },
  });
}
