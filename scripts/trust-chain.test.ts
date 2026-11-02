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
import { acceptFirstUse, saveTrustChain, trustPath } from './trust-chain.mjs';

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
    '[elsewhere]',
    'basicConstraints = critical, CA:FALSE',
    'keyUsage = critical, digitalSignature, keyEncipherment',
    'extendedKeyUsage = serverAuth',
    'subjectAltName = DNS:elsewhere.example',
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
  // The same chain, a leaf for another name: the trust file must not be enough on its own.
  issue('elsewhere', '/CN=elsewhere.example', 'issuing', 'elsewhere');
  const pem = (name: string) => readFileSync(join(work, `${name}.pem`), 'utf8').trim();
  return {
    key: readFileSync(join(work, 'leaf.key')),
    elsewhereKey: readFileSync(join(work, 'elsewhere.key')),
    elsewhere: `${pem('elsewhere')}\n${pem('issuing')}\n${pem('intermediate')}\n`,
    presented: `${pem('leaf')}\n${pem('issuing')}\n${pem('intermediate')}\n`,
    published: `${pem('leaf')}\n${pem('issuing')}\n${pem('intermediate')}\n${pem('root')}\n`,
    root: new X509Certificate(pem('root')),
  };
}

describe('the iya-sts trust chain in tlsCa', () => {
  const work = mkdtempSync(join(tmpdir(), 'gnap-tlsca-'));
  const chain = makeChain(work);
  let server: https.Server;
  let elsewhere: https.Server;
  let origin = '';
  let elsewherePort = 0;

  const handler: https.RequestListener = (req, res) => {
    if (req.url === '/tls/server-certificate') {
      res.setHeader('content-type', 'text/plain');
      res.end(chain.published);
      return;
    }
    if (req.url === '/gnap' && req.method === 'OPTIONS') {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({
        grant_request_endpoint: `https://${req.headers.host}/gnap`,
        interaction_start_modes_supported: ['redirect'],
        interaction_finish_methods_supported: ['redirect'],
        key_proofs_supported: ['mtls', 'httpsig'],
      }));
      return;
    }
    res.statusCode = 404;
    res.end();
  };

  before(async () => {
    server = https.createServer({ key: chain.key, cert: chain.presented }, handler);
    await new Promise<void>((done) => server.listen(0, '127.0.0.1', () => done()));
    origin = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
    elsewhere = https.createServer({ key: chain.elsewhereKey, cert: chain.elsewhere }, handler);
    await new Promise<void>((done) => elsewhere.listen(0, '127.0.0.1', () => done()));
    elsewherePort = (elsewhere.address() as AddressInfo).port;
  });

  after(async () => {
    await new Promise<void>((done) => server.close(() => done()));
    await new Promise<void>((done) => elsewhere.close(() => done()));
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
    assert.equal(saved.verified, false, 'no file yet: trust on first use');
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

  it('a later refresh verifies the server against the chain the file already holds', async () => {
    const dest = join(demo, 'generated/idp-ca.pem');
    const saved = await saveTrustChain(origin, dest);
    assert.equal(saved.verified, true);
    assert.equal(saved.anchor.fingerprint256, chain.root.fingerprint256);
  });

  it('a held chain that verifies the server is not given up for a host name the leaf does not carry', async () => {
    const dest = join(work, 'held-elsewhere.pem');
    copyFileSync(join(demo, 'generated/idp-ca.pem'), dest);
    await assert.rejects(saveTrustChain(`https://127.0.0.1:${elsewherePort}`, dest), /altnames|Hostname/);
    assert.equal(readFileSync(dest, 'utf8'), readFileSync(join(demo, 'generated/idp-ca.pem'), 'utf8'));
  });

  it('a held chain from another CA (a restarted development iya-sts) is replaced on first use', async () => {
    const other = mkdtempSync(join(tmpdir(), 'gnap-tlsca-other-'));
    const stale = makeChain(other);
    const dest = join(work, 'stale.pem');
    writeFileSync(dest, stale.published);
    const saved = await saveTrustChain(origin, dest);
    assert.equal(saved.verified, false);
    assert.equal(saved.anchor.fingerprint256, chain.root.fingerprint256);
    assert.notEqual(saved.anchor.fingerprint256, stale.root.fingerprint256);
  });

  it('first use checks the host name, the presented leaf, and every link of the chain', async () => {
    const certs = (chain.published.match(BLOCK) ?? []).map((pem) => new X509Certificate(pem));
    const [leaf, issuing, intermediate, root] = certs as [X509Certificate, X509Certificate, X509Certificate, X509Certificate];
    acceptFirstUse('127.0.0.1', { certs, leaf });
    assert.throws(() => acceptFirstUse('elsewhere.example', { certs, leaf }), /altnames|Hostname/);
    assert.throws(() => acceptFirstUse('127.0.0.1', { certs, leaf: issuing }), /handshake presented/);
    assert.throws(() => acceptFirstUse('127.0.0.1', { certs: [leaf, intermediate, root], leaf }), /not signed/);
    assert.throws(() => acceptFirstUse('127.0.0.1', { certs: [], leaf }), /no certificates/);
    // Without a held chain, a server whose leaf does not name the host is refused too.
    await assert.rejects(saveTrustChain(`https://127.0.0.1:${elsewherePort}`, join(work, 'none.pem')));
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

  it('the library checks the host name as well as the chain', async () => {
    const tls = GnapClient.create(readConfigFile(config)).tls();
    // The right leaf, by its IP address SAN and by its DNS SAN.
    const port = new URL(origin).port;
    assert.equal((await discoverGrantServer(`https://127.0.0.1:${port}/gnap`, tls)).grant_request_endpoint,
      `https://127.0.0.1:${port}/gnap`);
    assert.equal((await discoverGrantServer(`https://localhost:${port}/gnap`, tls)).grant_request_endpoint,
      `https://localhost:${port}/gnap`);
    // The same trusted chain, a leaf for another name: refused.
    await assert.rejects(discoverGrantServer(`https://127.0.0.1:${elsewherePort}/gnap`, tls), /altnames/);
  });
});
