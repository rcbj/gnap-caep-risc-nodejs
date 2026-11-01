// `signals` defaults to on. `false` drops the Shared Signals rights and does not fill a transmitter.

import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { describe, it } from 'node:test';
import { resolveConfig } from '../src/config.ts';
import { GnapError } from '../src/errors.ts';

const privateKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' });

function resolve(extra: Record<string, unknown> = {}) {
  return resolveConfig({
    grantEndpoint: 'https://idp.example/gnap',
    application: 'app',
    privateKey,
    keyProof: 'httpsig',
    ...extra,
  }, process.cwd());
}

describe('signals', () => {
  it('defaults access to ssf.read and ssf.manage and fills ssf from transmitterIssuer', () => {
    const resolved = resolve({ transmitterIssuer: 'https://idp.example/issuer/' });
    assert.deepEqual(resolved.access, ['ssf.read', 'ssf.manage']);
    assert.deepEqual(resolved.ssf, { transmitter: 'https://idp.example/issuer' });
    assert.equal(Object.hasOwn(resolved, 'signals'), false);
    const on = resolve({ signals: true, transmitterIssuer: 'https://idp.example/issuer' });
    assert.equal(Object.hasOwn(on, 'signals'), false);
    assert.ok(on.ssf);
  });

  it('drops ssf rights and the transmitter when signals is false', () => {
    const resolved = resolve({
      signals: false,
      access: ['openid', 'ssf.read'],
      transmitterIssuer: 'https://idp.example',
      ssf: { transmitter: 'https://idp.example/tx', pollIntervalMs: 3000 },
    });
    assert.deepEqual(resolved.access, ['openid']);
    assert.equal(Object.hasOwn(resolved, 'ssf'), false);
    assert.equal(resolved.signals, false);
    const kept = resolve({
      signals: false,
      access: ['openid', ' ssf.read ', { type: 'ssf.manage', actions: ['read'] }, { type: 'api' }, { type: ' ssf.read ' }],
      ssf: { transmitter: 'not a url' },
    });
    assert.deepEqual(kept.access, ['openid', { type: 'api' }, { type: ' ssf.read ' }]);
    assert.equal(Object.hasOwn(kept, 'ssf'), false);
  });

  it('refuses signals off when ssf.read and ssf.manage were the only rights', () => {
    const message = /signals is false and access has no rights left after ssf\.read and ssf\.manage were removed/;
    assert.throws(() => resolve({ signals: false, access: ['ssf.read', 'ssf.manage'] }), (err: unknown) => {
      assert.ok(err instanceof GnapError);
      assert.equal(err.code, 'config');
      assert.match(err.message, message);
      assert.match(err.message, /must name a right this authorization server grants/);
      return true;
    });
    assert.throws(() => resolve({ signals: false, transmitterIssuer: 'https://idp.example' }), message);
    assert.throws(() => resolve({ signals: false, access: [{ type: 'ssf.read' }, { type: 'ssf.manage' }] }), message);
  });

  it('refuses a signals value that is not true or false', () => {
    assert.throws(() => resolve({ signals: 'no' }), (err: unknown) => {
      assert.ok(err instanceof GnapError);
      assert.equal(err.code, 'config');
      assert.equal(err.message, 'signals must be true or false');
      return true;
    });
  });
});
