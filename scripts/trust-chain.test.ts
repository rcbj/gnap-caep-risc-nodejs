// tlsCa end to end, offline: the install script's saveTrustChain writes iya-sts's whole listener CA
// trust chain (leaf, TLS Issuing CA, Intermediate, Root) to the file demo/gnap.json's tlsCa names,
// and the library trusts an HTTPS grant server through that file as it is.
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createSelfSignedKeyPair, discoverGrantServer, GnapClient, readConfigFile } from '../packages/gnap-caep-risc-nodejs/src/index.ts';
import { saveTrustChain, trustPath } from './trust-chain.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

/** A four-certificate chain shaped like iya-sts's: Root, Intermediate, TLS Issuing CA, leaf. */
function makeChain(work: string) {
  const openssl = (...args: string[]) => execFileSync('openssl', args, { stdio: 'ignore' });
  const ext = join(work, 'ext.cnf');
  writeFileSync(ext, [
    '[ca]',
    'basicConstraints = critical, CA:TRUE',
    'keyUsage = critical, keyCertSign, cRLSign',
    '[leaf]',
    'basicConstraints = critical, CA:FALSE',
    'keyUsage = critical, digitalSignature, keyEncipherment',
    'extendedKeyUsage = serverAuth',
    'subjectAltName = IP:127.0.0.1, DNS:localhost',
    '',
  ].join('\n'));
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=sts Root CA',
    '-keyout', join(work, 'root.key'), '-out', join(work, 'root.pem'));
  const issue = (name: string, subject: string, issuer: string, section: string) => {
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', subject,
      '-keyout', join(work, `${name}.key`), '-out', join(work, `${name}.csr`));
    openssl('x509', '-req', '-in', join(work, `${name}.csr`), '-days', '1', '-set_serial', String(Date.now()),
      '-CA', join(work, `${issuer}.pem`), '-CAkey', join(work, `${issuer}.key`),
      '-extfile', ext, '-extensions', section, '-out', join(work, `${name}.pem`));
  };
  issue('intermediate', '/CN=sts Intermediate CA', 'root', 'ca');
  issue('issuing', '/CN=sts TLS Issuing CA', 'intermediate', 'ca');
  issue('leaf', '/CN=localhost', 'issuing', 'leaf');
  const pem = (name: string) => readFileSync(join(work, `${name}.pem`), 'utf8').trim();
  return {
    key: readFileSync(join(work, 'leaf.key')),
    presented: `${pem('leaf')}\n${pem('issuing')}\n${pem('intermediate')}\n`,
    published: `${pem('leaf')}\n${pem('issuing')}\n${pem('intermediate')}\n${pem('root')}\n`,
    root: new X509Certificate(pem('root')),
  };
}

describe('the iya-sts trust chain in tlsCa', () => {
  const work = mkdtempSync(join(tmpdir(), 'gnap-tlsca-'));
  const chain = makeChain(work);
  let server: https.Server;
  let origin = '';

  before(async () => {
    server = https.createServer({ key: chain.key, cert: chain.presented }, (req, res) => {
      if (req.url === '/tls/server-certificate') {
        res.setHeader('content-type', 'text/plain');
        res.end(chain.published);
        return;
      }
      if (req.url === '/gnap' && req.method === 'OPTIONS') {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({
          grant_request_endpoint: `${origin}/gnap`,
          interaction_start_modes_supported: ['redirect'],
          interaction_finish_methods_supported: ['redirect'],
          key_proofs_supported: ['mtls', 'httpsig'],
        }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    await new Promise<void>((done) => server.listen(0, '127.0.0.1', () => done()));
    origin = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  after(async () => {
    await new Promise<void>((done) => server.close(() => done()));
  });

  // demo/gnap.json as shipped, in a scratch demo directory, so tlsCa resolves as it does in the image.
  const demo = join(work, 'demo');
  const config = join(demo, 'gnap.json');

  it('the install script writes the whole chain to the file tlsCa names', async () => {
    mkdirSync(demo, { recursive: true });
    copyFileSync(join(repoRoot, 'demo/gnap.json'), config);
    const raw = JSON.parse(readFileSync(config, 'utf8')) as { tlsCa: string };
    assert.equal(raw.tlsCa, 'generated/idp-ca.pem');
    const dest = trustPath(raw.tlsCa, demo);
    assert.equal(dest, join(demo, 'generated/idp-ca.pem'));
    const saved = await saveTrustChain(origin, dest);
    assert.equal(saved.count, 4);
    assert.equal(saved.anchor.fingerprint256, chain.root.fingerprint256);
    const written = readFileSync(dest!, 'utf8').match(BLOCK) ?? [];
    const expected = chain.published.match(BLOCK) ?? [];
    assert.equal(written.length, 4);
    assert.deepEqual(
      written.map((pem) => new X509Certificate(pem).fingerprint256),
      expected.map((pem) => new X509Certificate(pem).fingerprint256),
    );
    assert.equal(new X509Certificate(written[3]!).subject, 'CN=sts Root CA');
  });

  it('the library trusts the grant server through that file, and not without it', async () => {
    const doc = JSON.parse(readFileSync(config, 'utf8')) as Record<string, unknown>;
    doc.grantEndpoint = `${origin}/gnap`;
    doc.transmitterIssuer = origin;
    doc.idTokenIssuer = origin;
    doc.ssf = { transmitter: origin };
    const pair = createSelfSignedKeyPair({ commonName: 'localhost' });
    writeFileSync(join(demo, 'generated/client.key'), pair.privateKeyPem);
    writeFileSync(join(demo, 'generated/client.crt'), pair.certificatePem);
    writeFileSync(config, JSON.stringify(doc));
    const resolved = readConfigFile(config);
    assert.equal(resolved.tlsCa, readFileSync(join(demo, 'generated/idp-ca.pem'), 'utf8'));
    const tls = GnapClient.create(resolved).tls();
    assert.equal(tls.ca, resolved.tlsCa);
    const metadata = await discoverGrantServer(resolved.grantEndpoint, tls);
    assert.equal(metadata.grant_request_endpoint, `${origin}/gnap`);
    const { ca: _ca, ...withoutCa } = tls;
    await assert.rejects(discoverGrantServer(resolved.grantEndpoint, withoutCa));
  });
});
