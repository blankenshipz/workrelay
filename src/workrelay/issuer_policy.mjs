// Unmounted policy prototype for the maintained oidc-provider. Never route
// requests here until private provisioning, login, consent and CSRF are ready.
import Provider, { errors } from 'oidc-provider';

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

export function createUnexposedIssuerPolicy({ origin, principal, jwks, cookieKeys, clientId,
  redirectUris, adapter, findAccount, clientRegistration = 'static', fetchClientDocument }) {
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
  return new Provider(issuer.origin, {
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
      if (ctx.oidc.route !== 'token' || ctx.oidc.params.resource !== resource ||
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
