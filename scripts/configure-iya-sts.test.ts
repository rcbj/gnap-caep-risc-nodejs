// The setup script's plan, offline: a registered GNAP key, no class_id, no secret rotation, the full chain.
import assert from 'node:assert/strict';
import https from 'node:https';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { createSelfSignedKeyPair } from '../packages/gnap-caep-risc-nodejs/src/x509.ts';
import {
  DEFAULT_LISTENER_CA, MULTIPLE_ACCOUNTS, SSF_ROLES, adminTls, fetchTlsChain, filesOf, idpFromGrant,
  listenerCaTarget, parseArgs, planFor, realmOf, userAttributes, writeListenerCa,
} from './configure-iya-sts.ts';

describe('configure-iya-sts', () => {
  const dir = mkdtempSync(join(tmpdir(), 'gnap-setup-'));
  const config = join(dir, 'gnap.json');
  writeFileSync(config, JSON.stringify({
    grantEndpoint: 'https://localhost:8081/gnap',
    application: 'gnap-caep-risc-demo',
    display: { name: 'GNAP CAEP RISC demo', uri: 'http://localhost:3000/' },
    access: ['ssf.read', 'ssf.manage'],
    keyProof: 'mtls',
    privateKey: 'file:generated/client.key',
    certificate: 'file:generated/client.crt',
    finishUri: 'http://localhost:3000/callback',
    interactionStart: ['redirect'],
    tlsCa: 'generated/idp-ca.pem',
    ssf: { transmitter: 'https://localhost:8081' },
  }));

  it('reads the file, and prefers its finish URI over --public-url', () => {
    const files = filesOf(config, 'http://other.example:9');
    assert.equal(files.application, 'gnap-caep-risc-demo');
    assert.equal(files.finishUri, 'http://localhost:3000/callback');
    assert.equal(files.displayUri, 'http://localhost:3000/');
    assert.equal(files.name, 'GNAP CAEP RISC demo');
    assert.equal(files.tlsCa, join(dir, 'generated/idp-ca.pem'));
    assert.deepEqual(files.scopes, ['ssf.read', 'ssf.manage']);
    assert.equal(files.keyProof, 'mtls');
    assert.equal(idpFromGrant(files.grantEndpoint), 'https://localhost:8081');
  });

  it('registers a GNAP client and does not send the key again when the application exists', () => {
    const files = filesOf(config, 'http://localhost:3000');
    const keyJson = JSON.stringify({ proof: 'mtls', cert: 'PEM' });
    const plan = planFor(files, 'https://localhost:8081', 'gnap-demo-user', keyJson);
    const create = plan.find((call) => call.when === 'create');
    assert.ok(create);
    assert.match(create.path, /\/admin-api\/applications\/create$/);
    const body = create.body as {
      identifier: string; name: string; kind: string; protocols: string[]; fields: Record<string, unknown>;
    };
    assert.equal(body.identifier, 'gnap-caep-risc-demo');
    assert.equal(body.name, 'GNAP CAEP RISC demo');
    assert.equal(body.kind, 'gnap-client');
    assert.deepEqual(body.protocols, ['gnap']);
    assert.equal(body.fields.gnapKey, keyJson);
    assert.deepEqual(body.fields.gnapFinishUri, ['http://localhost:3000/callback']);
    assert.deepEqual(body.fields.gnapInteractionStartModes, ['redirect']);
    assert.equal(body.fields.gnapBearerTokens, 'FALSE');
    assert.equal(body.fields.gnapDisplayUri, 'http://localhost:3000/');
    assert.deepEqual(body.fields.oauthAllowedScope, files.scopes);
    const text = JSON.stringify(body);
    assert.equal(text.includes('class_id'), false);
    assert.equal(text.includes('gnapClassId'), false);
    assert.equal(text.includes('appCorsOrigin'), false);
    const again = plan.filter((call) => call.when === 'exists').map((call) => JSON.stringify(call.body));
    assert.ok(again.length > 0);
    assert.ok(again.every((line) => !line.includes('gnapKey') && !line.includes('class_id')));
    assert.ok(again.some((line) => line.includes('gnapBearerTokens') && line.includes('FALSE')));
    assert.deepEqual(plan.find((call) => call.path.endsWith('/config/set'))?.body, MULTIPLE_ACCOUNTS);
    const roles = plan.filter((call) => call.path.endsWith('/roles/add-member')).map((call) => (call.body as { role: string }).role);
    assert.deepEqual(roles, SSF_ROLES.map((role) => role.role));
    const user = plan.find((call) => call.path.endsWith('/users/create'));
    assert.deepEqual((user?.body as { username: string }).username, 'gnap-demo-user');
    assert.deepEqual((user?.body as { attributes: Record<string, string> }).attributes, userAttributes('gnap-demo-user'));
    const groups = plan.filter((call) => call.path.endsWith('/groups/add-member')).map((call) => (call.body as { group: string }).group);
    assert.deepEqual(groups, ['ssf-read', 'ssf-manage']);
    assert.equal(planFor(files, 'https://localhost:8081', '', keyJson).some((call) => call.path.endsWith('/users/create')), false);
    assert.equal(adminTls().rejectUnauthorized, false);
  });

  it('keeps a realm base and refuses any other path', () => {
    assert.deepEqual(realmOf('https://idp.test/realm/acme'), { origin: 'https://idp.test', base: 'https://idp.test/realm/acme' });
    assert.equal(idpFromGrant('https://idp.test/realm/acme/gnap'), 'https://idp.test/realm/acme');
    assert.throws(() => realmOf('https://idp.test/oauth2'), /realm/);
    assert.throws(() => realmOf('http://idp.test'), /https/);
  });

  it('takes its options', () => {
    const args = parseArgs(['--idp', 'https://idp.test/', '--public-url', 'http://app.test/', '--no-test-user', '--dry-run'], {});
    assert.equal(args.idp, 'https://idp.test');
    assert.equal(args.publicUrl, 'http://app.test');
    assert.equal(args.testUser, '');
    assert.equal(args.dryRun, true);
    assert.equal(args.config.endsWith('/demo/gnap.json'), true);
    assert.throws(() => parseArgs(['--idp', 'http://idp.test'], {}), /https/);
    assert.throws(() => parseArgs(['--bogus'], {}), /Unknown argument/);
  });

  it('sets tlsCa to the file that holds the listener chain', () => {
    const bare = join(dir, 'bare.json');
    writeFileSync(bare, JSON.stringify({ grantEndpoint: 'https://idp.example/gnap', application: 'app' }));
    const pem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';
    const saved = writeListenerCa(bare, pem);
    assert.equal(saved.parameter, DEFAULT_LISTENER_CA);
    assert.equal(readFileSync(saved.file!, 'utf8'), pem);
    const written = JSON.parse(readFileSync(bare, 'utf8')) as { tlsCa: string; application: string };
    assert.equal(written.tlsCa, DEFAULT_LISTENER_CA);
    assert.equal(written.application, 'app');
    const again = writeListenerCa(bare, pem);
    assert.equal(again.parameter, DEFAULT_LISTENER_CA);
    const pinned = join(dir, 'env.json');
    writeFileSync(pinned, `${JSON.stringify({ tlsCa: 'env:STS_LISTENER_CA', application: 'app' })}\n`);
    const left = writeListenerCa(pinned, pem);
    assert.equal(left.parameter, 'env:STS_LISTENER_CA');
    assert.equal(left.file, undefined);
    assert.equal(readFileSync(pinned, 'utf8'), `${JSON.stringify({ tlsCa: 'env:STS_LISTENER_CA', application: 'app' })}\n`);
    assert.deepEqual(listenerCaTarget(bare, 'file:keys/ca.pem'), {
      parameter: 'keys/ca.pem',
      file: join(dir, 'keys/ca.pem'),
    });
  });

  it('saves every certificate in the handshake', async () => {
    const pair = createSelfSignedKeyPair({ commonName: 'localhost', dns: ['localhost'], ip: ['127.0.0.1'] });
    const server = https.createServer({ key: pair.privateKeyPem, cert: pair.certificatePem }, (_req, res) => {
      res.end('ok');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const port = (server.address() as AddressInfo).port;
      const chain = await fetchTlsChain(`https://127.0.0.1:${port}`);
      assert.match(chain.pem, /BEGIN CERTIFICATE/);
      assert.equal(chain.count, 1);
      assert.equal(chain.leaf.fingerprint256, pair.certificate.fingerprint256);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
