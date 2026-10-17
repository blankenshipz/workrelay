import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createPinnedWebhookTransport, createCallbackResolver } from '../src/workrelay/events.mjs';
const destination = 'https://receiver.example/callback?secret=SYNTHETIC_PRIVATE_QUERY';
const wire = { body: '{}', headers: {} };
const publicDNS = async () => [{ address: '8.8.8.8', family: 4 }];
function safe(error, phase, code) {
  assert.deepEqual(error.data, { reason: 'network_error', phase, native_code: code });
  assert.ok(!JSON.stringify(error).includes('SYNTHETIC_PRIVATE')); return true;
}
test('DNS diagnostics retain finite native category, never hostname/query/message/cause', async () => {
  const transport = createPinnedWebhookTransport({ resolve: async () => { throw Object.assign(new Error('SYNTHETIC_PRIVATE_QUERY receiver path'), { code: 'ENOTFOUND', hostname: 'SYNTHETIC_PRIVATE_HOST', cause: { password: 'SYNTHETIC_PRIVATE' } }); } });
  await assert.rejects(transport(destination, wire), error => safe(error, 'dns', 'ENOTFOUND'));
  const unknown = createPinnedWebhookTransport({ resolve: async () => { throw { code: 'SYNTHETIC_PRIVATE', message: 'SYNTHETIC_PRIVATE' }; } });
  await assert.rejects(unknown(destination, wire), error => safe(error, 'dns', 'OTHER_NETWORK_ERROR'));
});
test('connect/TLS diagnostics preserve mandatory hostname pinning and certificate verification', async () => {
  for (const [phase, code] of [['connect', 'ENETUNREACH'], ['tls', 'CERT_HAS_EXPIRED']]) {
    const transport = createPinnedWebhookTransport({ resolve: publicDNS, request: (_url, options) => {
      assert.equal(options.servername, 'receiver.example'); assert.equal(options.rejectUnauthorized, true); assert.equal(options.agent, false);
      options.lookup('receiver.example', { all: true }, (error, addresses) => { assert.equal(error, null); assert.deepEqual(addresses, [{ address: '8.8.8.8', family: 4 }]); });
      const req = new EventEmitter(); req.destroy = () => {};
      req.end = () => queueMicrotask(() => { const socket = new EventEmitter(); req.emit('socket', socket); if (phase === 'tls') socket.emit('connect'); req.emit('error', Object.assign(new Error('SYNTHETIC_PRIVATE'), { code })); }); return req;
    } });
    await assert.rejects(transport(destination, wire), error => safe(error, phase, code));
  }
});

test('configured DNS fallback handles AAAA-only names but never bypasses private-answer rejection', async () => {
  const absent = async () => { throw Object.assign(new Error('no answer'), { code: 'ENOTFOUND' }); };
  const resolver = createCallbackResolver({ osLookup: absent, ipv4: absent, ipv6: async () => ['2606:4700:4700::1111'] });
  assert.deepEqual(await resolver('receiver.example', { all: true }), [{ address: '2606:4700:4700::1111', family: 6 }]);
  let fallbackCalls = 0;
  const privateResolver = createCallbackResolver({ osLookup: async () => [{ address: '127.0.0.1', family: 4 }], ipv4: async () => { fallbackCalls++; return ['8.8.8.8']; }, ipv6: async () => [] });
  await assert.rejects(createPinnedWebhookTransport({ resolve: privateResolver, request: () => assert.fail('must not connect') })(destination, wire), e => e.data.reason === 'non_public_address');
  assert.equal(fallbackCalls, 0);
  const mixed = createCallbackResolver({ osLookup: absent, ipv4: async () => ['8.8.8.8'], ipv6: async () => ['::1'] });
  await assert.rejects(createPinnedWebhookTransport({ resolve: mixed, request: () => assert.fail('must reject mixed answers') })(destination, wire), e => e.data.reason === 'non_public_address');
});
