// Unmounted policy prototype for the maintained oidc-provider. Never route
// requests here until private provisioning, login, consent and CSRF are ready.
import Provider, { errors } from 'oidc-provider';

const exactHttps = (value, allowOrigin = false) => {
  if (typeof value !== 'string' || value.length > 2048) throw Error('invalid issuer policy');
  const uri = new URL(value);
  if (uri.protocol !== 'https:' || uri.username || uri.password || uri.hash ||
      (uri.href !== value && !(allowOrigin && uri.origin === value)) || uri.hostname.includes('*')) throw Error('invalid issuer policy');
  return uri;
};

export function createUnexposedIssuerPolicy({ origin, principal, jwks, cookieKeys, clientId,
  redirectUris, adapter, findAccount }) {
  const issuer = exactHttps(origin, true);
  if (issuer.pathname !== '/' || issuer.search || !principal || typeof principal !== 'string' ||
      !Array.isArray(jwks?.keys) || !jwks.keys.length ||
      !Array.isArray(cookieKeys) || !cookieKeys.length || cookieKeys.some(key => typeof key !== 'string' || key.length < 32) ||
      typeof clientId !== 'string' || !clientId || !Array.isArray(redirectUris) || !redirectUris.length ||
      typeof adapter !== 'function' || typeof findAccount !== 'function') throw Error('invalid issuer policy');
  const allowed = redirectUris.map(uri => exactHttps(uri).href);
  if (new Set(allowed).size !== allowed.length) throw Error('invalid issuer policy');
  const resource = `${issuer.origin}/mcp`;
  return new Provider(issuer.origin, {
    adapter, jwks, cookies: { keys: cookieKeys, long: { httpOnly: true, secure: true, sameSite: 'lax' },
      short: { httpOnly: true, secure: true, sameSite: 'lax' } },
    clients: [{ client_id: clientId, redirect_uris: allowed,
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
      clientIdMetadataDocument: { enabled: false },
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
