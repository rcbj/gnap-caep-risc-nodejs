// Inputs that made a regular expression quadratic (CodeQL js/polynomial-redos) finish in linear time
// and still give the same answer.

import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { describe, it } from 'node:test';
import { resolveConfig } from '../src/config.ts';
import { wellKnownUrls } from '../src/discovery.ts';
import { certificateBlocks } from '../src/keys.ts';
import { SignalsReceiver } from '../src/ssf/receiver.ts';
import { trimTrailingSlashes } from '../src/text.ts';
import { createSelfSignedKeyPair } from '../src/x509.ts';

const N = 100_000;
const LIMIT_MS = 500;
const slashes = `https://idp.example/${'/'.repeat(N)}x`;
const privateKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' });

function timed<T>(run: () => T): T {
  const start = performance.now();
  const value = run();
  const ms = performance.now() - start;
  assert.ok(ms < LIMIT_MS, `took ${Math.round(ms)} ms`);
  return value;
}

describe('trailing slashes', () => {
  it('are trimmed and only at the end', () => {
    assert.equal(trimTrailingSlashes('https://a.example/x///'), 'https://a.example/x');
    assert.equal(trimTrailingSlashes('https://a.example/x'), 'https://a.example/x');
    assert.equal(trimTrailingSlashes('///'), '');
    assert.equal(trimTrailingSlashes(''), '');
    assert.equal(timed(() => trimTrailingSlashes(slashes)), slashes);
  });

  it('in idTokenIssuer and the transmitter, on a long run of slashes', () => {
    const resolved = timed(() => resolveConfig({
      grantEndpoint: 'https://idp.example/gnap',
      application: 'app',
      privateKey,
      keyProof: 'httpsig',
      idTokenIssuer: slashes,
      ssf: { transmitter: slashes },
    }, process.cwd()));
    assert.equal(resolved.idTokenIssuer, slashes);
    assert.equal(resolved.ssf?.transmitter, slashes);
    const trimmed = resolveConfig({
      grantEndpoint: 'https://idp.example/gnap',
      application: 'app',
      privateKey,
      keyProof: 'httpsig',
      idTokenIssuer: 'https://idp.example/issuer//',
      transmitterIssuer: 'https://idp.example/tx/',
    }, process.cwd());
    assert.equal(trimmed.idTokenIssuer, 'https://idp.example/issuer');
    assert.equal(trimmed.ssf?.transmitter, 'https://idp.example/tx');
  });

  it('in the receiver transmitter and the well-known URLs', () => {
    const receiver = timed(() => new SignalsReceiver({ transmitter: slashes, onEndSessions: () => {} }));
    assert.ok(receiver);
    assert.deepEqual(wellKnownUrls('https://idp.example/realm/', 'ssf-configuration'), [
      'https://idp.example/.well-known/ssf-configuration/realm',
      'https://idp.example/realm/.well-known/ssf-configuration',
    ]);
    timed(() => wellKnownUrls(slashes, 'openid-configuration'));
  });
});

describe('certificate blocks', () => {
  it('are found in order, and many BEGIN lines with no END are linear', () => {
    const a = createSelfSignedKeyPair({ commonName: 'a.example' }).certificatePem.trim();
    const b = createSelfSignedKeyPair({ commonName: 'b.example' }).certificatePem.trim();
    assert.deepEqual(certificateBlocks(`junk\n${a}\nmore\n${b}\n`), [a, b]);
    assert.deepEqual(certificateBlocks('no certificate here'), []);
    const hostile = '-----BEGIN CERTIFICATE-----\n'.repeat(N / 4);
    assert.deepEqual(timed(() => certificateBlocks(hostile)), []);
  });
});
