import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { personWithAccessTokenUid, uidFromAccessToken } from '../demo/uid-claim.ts';

function jwt(payload: unknown): string {
  const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${part({ alg: 'EdDSA' })}.${part(payload)}.sig`;
}

describe('access-token uid claim', () => {
  it('reads a string uid and ignores every other shape', () => {
    assert.equal(uidFromAccessToken(jwt({ uid: 'ada', sub: 'urn:uuid:ada' })), 'ada');
    assert.equal(uidFromAccessToken(jwt({ uid: '' })), undefined);
    assert.equal(uidFromAccessToken(jwt({ uid: 3 })), undefined);
    assert.equal(uidFromAccessToken(jwt({ sub: 'urn:uuid:ada' })), undefined);
    assert.equal(uidFromAccessToken('not-a-jwt'), undefined);
    assert.equal(uidFromAccessToken('a.%%%'), undefined);
  });

  it('prefers the claim over the account identifier, and keeps that identifier when the claim is absent', () => {
    const account = { sub: 'urn:uuid:ada', uid: 'from-account' };
    assert.deepEqual(personWithAccessTokenUid(account, jwt({ uid: 'from-token' })), {
      sub: 'urn:uuid:ada', uid: 'from-token',
    });
    assert.equal(personWithAccessTokenUid(account, jwt({ sub: 'urn:uuid:ada' })), account);
    assert.equal(personWithAccessTokenUid(account, 'opaque-token'), account);
  });
});
