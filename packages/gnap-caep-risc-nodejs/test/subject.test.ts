// The directory username is the user part of an account subject identifier. The protocol subject stays sub.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { personFrom, type SubjectCheck } from '../src/subject.ts';

const check: SubjectCheck = {
  idTokenIssuer: 'https://as.example',
  audiences: [],
  clockToleranceSec: 0,
  keys: async () => [],
};

describe('personFrom account username', () => {
  it('takes the uid from an account identifier and keeps the protocol subject', async () => {
    const person = await personFrom({
      sub_ids: [
        { format: 'iss_sub', iss: 'https://as.example', sub: 'urn:uuid:abc' },
        { format: 'account', uri: 'acct:gnap-demo-user@localhost:8081' },
      ],
    }, check);
    assert.equal(person?.sub, 'urn:uuid:abc');
    assert.equal(person?.iss, 'https://as.example');
    assert.equal(person?.uid, 'gnap-demo-user');
  });

  it('percent-decodes the user part and keeps a part that is not valid encoding', async () => {
    const decoded = await personFrom({
      sub_ids: [{ format: 'account', uri: 'acct:ada%20lovelace@idp.example' }],
    }, check);
    assert.equal(decoded?.sub, 'acct:ada%20lovelace@idp.example');
    assert.equal(decoded?.uid, 'ada lovelace');
    const kept = await personFrom({
      sub_ids: [{ format: 'account', uri: 'acct:%E0%A4%A@idp.example' }],
    }, check);
    assert.equal(kept?.uid, '%E0%A4%A');
  });

  it('leaves uid unset when the grant has no account identifier', async () => {
    const person = await personFrom({
      sub_ids: [{ format: 'iss_sub', iss: 'https://as.example', sub: 'urn:uuid:abc' }],
    }, check);
    assert.equal(person?.uid, undefined);
    assert.equal(person?.sub, 'urn:uuid:abc');
  });
});
