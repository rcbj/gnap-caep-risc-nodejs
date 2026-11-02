// The client against a stub authorization server. The stub verifies HTTP signatures and detached JWS
// with its own reconstruction of the signed input, not with the library's signer. The interaction hash
// vector is checked below; the stub's finish hash is hashed with node:crypto.

import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, sign, verify, X509Certificate, type KeyObject } from 'node:crypto';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import type { IncomingMessage } from 'node:http';
import { after, before, describe, it } from 'node:test';
import { GnapClient, GnapError, createSelfSignedKeyPair, interactionHash, loadClientKey, publicKeyObject, type KeyProof } from '../src/index.ts';

const idKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const idJwk = { ...idKeys.publicKey.export({ format: 'jwk' }), kid: 'id1', alg: 'RS256', use: 'sig' };

function idToken(issuer: string, aud: string, sub: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'id1', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(JSON.stringify({
    iss: issuer, aud, sub, exp: now + 600, iat: now, email: `${sub}@example.com`, sid: 'sess-1', name: 'Ada',
  })).toString('base64url');
  const sig = sign('sha256', Buffer.from(`${header}.${payload}`), idKeys.privateKey).toString('base64url');
  return `${header}.${payload}.${sig}`;
}

interface Seen {
  method: string;
  url: string;
  body: string;
  authorization: string;
  signature: string;
  detached: string;
  cert: string;
}

interface Behavior {
  foreign: boolean;
  bearer: boolean;
  tooFast: boolean;
  aud: string;
  sub: string;
  /** When set, the subject identifier's sub differs from the ID token. */
  issSub?: string;
  omitToken: boolean;
  /** When set, the continuation URI the grant response names. */
  continueUri?: string;
  /** When set, the continuation URI a too_fast error names. */
  tooFastUri?: string;
}

function finishHash(clientNonce: string, interactRef: string, grantEndpoint: string): string {
  return createHash('sha256').update(`${clientNonce}\nserver-nonce\n${interactRef}\n${grantEndpoint}`).digest('base64url');
}

describe('the GNAP client', { concurrency: 1 }, () => {
  const serverKey = createSelfSignedKeyPair({ commonName: 'localhost', dns: ['localhost'], ip: ['127.0.0.1'] });
  const clientKey = createSelfSignedKeyPair({ commonName: 'gnap-client' });
  let base = '';
  let seen: Seen[] = [];
  let publicKey: KeyObject | undefined;
  let kid = '';
  const behavior: Behavior = { foreign: false, bearer: false, tooFast: false, aud: 'instance-1', sub: 'user-1', omitToken: false };
  let tooFastSent = false;
  let server: https.Server;
  // A second listener for the mutual TLS proof. It asks for a client certificate and refuses the
  // handshake unless the certificate is the one the client registered, which is how a GNAP
  // authorization server binds a self-signed key (RFC 9635 7.3.3). The first listener asks for no
  // certificate, because the httpsig and jwsd proofs present none.
  let mtlsServer: https.Server;
  let mtlsBase = '';

  function verifyHttpsig(req: IncomingMessage, raw: string, target: string): void {
    const input = String(req.headers['signature-input'] ?? '');
    assert.equal(/;alg=/.test(input), false, 'an httpsig proof must not carry an alg parameter');
    const match = /^sig1=\(([^)]*)\)(.*)$/.exec(input);
    assert.ok(match, `signature-input: ${input}`);
    const components = [...match[1]!.matchAll(/"([^"]+)"/g)].map((found) => found[1]!);
    const serialised = `(${components.map((c) => `"${c}"`).join(' ')})${match[2]}`;
    assert.match(match[2]!, /tag="gnap"/);
    assert.ok(match[2]!.includes(`keyid="${kid}"`), `keyid ${kid} in ${match[2]}`);
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(req.headers)) if (typeof value === 'string') headers[name] = value;
    const lines = components.map((component) => {
      let value = '';
      if (component === '@method') value = String(req.method).toUpperCase();
      else if (component === '@target-uri') value = target;
      else value = (headers[component] ?? '').trim();
      return `"${component}": ${value}`;
    });
    lines.push(`"@signature-params": ${serialised}`);
    const sig = /^sig1=:([A-Za-z0-9+/=]*):$/.exec(String(req.headers.signature ?? ''));
    assert.ok(sig, 'signature');
    const ok = verify('sha256', Buffer.from(lines.join('\n'), 'utf8'), { key: publicKey!, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig[1]!, 'base64'));
    assert.equal(ok, true, 'the HTTP message signature does not verify');
    if (raw.length) {
      const digest = `sha-256=:${createHash('sha256').update(raw).digest('base64')}:`;
      assert.equal(headers['content-digest'], digest);
    }
  }

  function verifyJwsd(req: IncomingMessage, raw: string, target: string): void {
    const parts = String(req.headers['detached-jws'] ?? '').split('.');
    assert.equal(parts.length, 3);
    const header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString()) as Record<string, unknown>;
    assert.equal(header.typ, 'gnap-binding-jwsd');
    assert.equal(header.alg, 'ES256');
    assert.equal(header.kid, kid);
    assert.equal(header.htm, String(req.method).toUpperCase());
    assert.equal(header.uri, target);
    const token = String(req.headers.authorization ?? '').replace(/^GNAP /, '');
    if (req.headers.authorization) {
      assert.equal(header.ath, createHash('sha256').update(Buffer.from(token, 'ascii')).digest('base64url'));
    } else assert.equal(header.ath, undefined);
    const payload = raw.length ? createHash('sha256').update(raw).digest('base64url') : '';
    assert.equal(parts[1], payload);
    const ok = verify('sha256', Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'), { key: publicKey!, dsaEncoding: 'ieee-p1363' }, Buffer.from(parts[2]!, 'base64url'));
    assert.equal(ok, true, 'the detached JWS does not verify');
  }

  function rememberKey(body: string): void {
    const doc = JSON.parse(body) as { client?: { key?: { jwk?: { kid?: string }; cert?: string } } | string };
    const key = doc.client && typeof doc.client === 'object' ? doc.client.key : undefined;
    if (key?.jwk) {
      publicKey = createPublicKey({ key: key.jwk, format: 'jwk' });
      kid = key.jwk.kid ?? '';
    }
  }

  function handle(req: IncomingMessage, res: import('node:http').ServerResponse): void {
    const chunks: Buffer[] = [];
    // Each listener answers with its own origin, so a client on either one stays on it.
    const base = `https://127.0.0.1:${req.socket.localPort}`;
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const url = new URL(req.url ?? '/', base);
      const target = `${base}${url.pathname}`;
      const peer = req.socket && 'getPeerCertificate' in req.socket ? (req.socket as import('node:tls').TLSSocket).getPeerCertificate() : undefined;
      seen.push({
        method: req.method ?? '',
        url: url.pathname,
        body: raw,
        authorization: String(req.headers.authorization ?? ''),
        signature: String(req.headers.signature ?? ''),
        detached: String(req.headers['detached-jws'] ?? ''),
        cert: peer?.raw ? new X509Certificate(peer.raw).fingerprint256 : '',
      });
      const send = (status: number, body?: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(body === undefined ? '' : JSON.stringify(body));
      };
      try {
        if (req.method === 'OPTIONS' && url.pathname === '/gnap') {
          return send(200, {
            grant_request_endpoint: `${base}/gnap`,
            key_proofs_supported: ['httpsig', 'jwsd', 'mtls'],
            interaction_start_modes_supported: ['redirect'],
            interaction_finish_methods_supported: ['redirect', 'push'],
            sub_id_formats_supported: ['iss_sub', 'opaque'],
            assertion_formats_supported: ['id_token'],
          });
        }
        if (url.pathname === '/.well-known/openid-configuration') {
          return send(200, { issuer: base, jwks_uri: `${base}/jwks` });
        }
        if (url.pathname === '/jwks') return send(200, { keys: [idJwk] });
        if (raw && url.pathname === '/gnap') rememberKey(raw);
        if (req.headers.signature) verifyHttpsig(req, raw, target);
        if (req.headers['detached-jws']) verifyJwsd(req, raw, target);
        if (url.pathname === '/gnap' && req.method === 'POST') {
          const cont = behavior.continueUri ?? (behavior.foreign ? 'https://evil.example/continue' : `${base}/continue`);
          return send(200, {
            instance_id: 'instance-1',
            interact: { redirect: `${base}/interact/1`, finish: 'server-nonce' },
            continue: { uri: cont, wait: 0, access_token: { value: 'cont-token' } },
          });
        }
        if (url.pathname === '/continue' && req.method === 'POST') {
          assert.equal(req.headers.authorization, 'GNAP cont-token');
          if (behavior.tooFast && !tooFastSent) {
            tooFastSent = true;
            return send(400, { error: 'too_fast', continue: { uri: behavior.tooFastUri ?? `${base}/continue`, wait: 0, access_token: { value: 'cont-token' } } });
          }
          if (behavior.omitToken) return send(200, { instance_id: 'instance-1' });
          const token = idToken(base, behavior.aud, behavior.sub);
          return send(200, {
            instance_id: 'instance-1',
            access_token: {
              value: 'access-1',
              access: ['ssf.read', 'ssf.manage'],
              expires_in: 3600,
              ...(behavior.bearer ? { flags: ['bearer'] } : {}),
              manage: { uri: `${base}/token/grant-9`, access_token: { value: 'manage-1' } },
            },
            continue: { uri: `${base}/continue/grant-9`, access_token: { value: 'cont-next' } },
            subject: {
              sub_ids: [{ format: 'iss_sub', iss: base, sub: behavior.issSub ?? behavior.sub }],
              assertions: [{ format: 'id_token', value: token }],
            },
          });
        }
        if (url.pathname === '/token/grant-9' && req.method === 'POST') {
          assert.equal(req.headers.authorization, 'GNAP manage-1');
          return send(200, { access_token: { value: 'access-2', expires_in: 3600, manage: { uri: `${base}/token/grant-9`, access_token: { value: 'manage-2' } } } });
        }
        if (req.method === 'DELETE') return send(204);
        return send(404, { error: 'not_found' });
      } catch (err) {
        send(401, { error: 'invalid_client', error_description: (err as Error).message });
      }
    });
  }

  async function listen(): Promise<void> {
    server = https.createServer({ key: serverKey.privateKeyPem, cert: serverKey.certificatePem }, handle);
    mtlsServer = https.createServer({
      key: serverKey.privateKeyPem,
      cert: serverKey.certificatePem,
      requestCert: true,
      ca: clientKey.certificatePem,
    }, handle);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    await new Promise<void>((resolve) => mtlsServer.listen(0, '127.0.0.1', resolve));
    base = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
    mtlsBase = `https://127.0.0.1:${(mtlsServer.address() as AddressInfo).port}`;
  }

  function client(proof: KeyProof, extra: Record<string, unknown> = {}): GnapClient {
    return GnapClient.create(GnapClient.resolve({
      grantEndpoint: `${base}/gnap`,
      idTokenIssuer: base,
      application: 'gnap-caep-risc-demo',
      display: { name: 'GNAP CAEP RISC demo', uri: 'http://127.0.0.1:3000/' },
      access: ['ssf.read', 'ssf.manage'],
      subIdFormats: ['iss_sub', 'account', 'opaque'],
      assertionFormats: ['id_token'],
      keyProof: proof,
      privateKey: clientKey.privateKeyPem,
      certificate: clientKey.certificatePem,
      finishUri: 'http://127.0.0.1:3000/callback',
      finishMethod: 'redirect',
      tlsCa: serverKey.certificatePem,
      ...extra,
    }, process.cwd()));
  }

  async function started(gnap: GnapClient) {
    const result = await gnap.requestGrant();
    assert.ok('pending' in result);
    const request = JSON.parse(seen.filter((call) => call.method === 'POST' && call.url === '/gnap').at(-1)!.body) as {
      client: { key?: { proof: string }; class_id?: string };
      subject: { sub_id_formats: string[] };
      interact: { finish: { method: string; nonce: string } };
    };
    return { result, request };
  }

  before(listen);
  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await new Promise<void>((resolve) => mtlsServer.close(() => resolve()));
  });

  it('refuses a bearer token, a front-channel token, a foreign continuation, and a hash that is not ours', async () => {
    assert.equal(interactionHash('abc', 'def', 'xyz', 'https://as.example/gnap'), '2o3b9NeEcvp0At5d-71yCgybP45eTGm1_pTNMmjv_V0');
    const gnap = client('httpsig');
    behavior.foreign = true;
    await assert.rejects(() => gnap.requestGrant(), (err: unknown) => err instanceof GnapError && /not on the grant endpoint/.test(err.message));
    assert.equal(seen.filter((call) => call.url === '/continue').length, 0);
    behavior.foreign = false;
    seen = [];
    // The refused response still carried an instance id, so a later grant from that client sends the
    // instance id rather than the key. A new client is what still presents the key by value.
    const presenting = client('httpsig');
    const { result, request } = await started(presenting);
    assert.equal(request.client.key?.proof, 'httpsig');
    assert.equal(request.client.class_id, undefined);
    assert.deepEqual(request.subject.sub_id_formats, ['iss_sub', 'opaque']);
    assert.equal(seen[seen.length - 1]!.signature.length > 0, true);
    const hash = finishHash(request.interact.finish.nonce, 'ref-1', `${base}/gnap`);
    await assert.rejects(
      () => presenting.finishRedirect(`hash=${hash}&interact_ref=ref-1&access_token=no`, { allowedIds: [result.pending.id] }),
      (err: unknown) => err instanceof GnapError && /front/.test(err.message) === false && /tokens through the browser/.test((err as GnapError).message),
    );
    await assert.rejects(
      () => presenting.finishRedirect(`hash=${hash}&interact_ref=ref-1`, { allowedIds: ['somebody-else'] }),
      /this browser/,
    );
    assert.equal(seen.filter((call) => call.url === '/continue').length, 0);
    await assert.rejects(() => presenting.finishRedirect('hash=nope&interact_ref=ref-1', { allowedIds: [result.pending.id] }), /this browser/);
  });

  it('finishes a redirect with an HTTP signature, checks the ID token, and rotates', async () => {
    seen = [];
    tooFastSent = false;
    behavior.tooFast = true;
    behavior.bearer = false;
    behavior.aud = 'instance-1';
    behavior.sub = 'user-1';
    delete behavior.issSub;
    const gnap = client('httpsig');
    const { result, request } = await started(gnap);
    const hash = finishHash(request.interact.finish.nonce, 'ref-1', `${base}/gnap`);
    const done = await gnap.finishRedirect({ hash, interact_ref: 'ref-1' }, { allowedIds: [result.pending.id] });
    assert.equal(done.grant.accessToken, 'access-1');
    assert.equal(done.grant.bearer, false);
    assert.equal(done.grant.subject?.sub, 'user-1');
    assert.equal(done.grant.subject?.email, 'user-1@example.com');
    assert.equal(done.grant.subject?.sid, 'sess-1');
    assert.equal(done.grant.subject?.assertionVerified, true);
    assert.equal(done.grant.grantId, 'grant-9');
    assert.equal(tooFastSent, true);
    const again = await gnap.requestGrant();
    assert.ok('pending' in again);
    const second = JSON.parse(seen.filter((call) => call.url === '/gnap').at(-1)!.body) as { client: unknown };
    assert.equal(second.client, 'instance-1');
    const rotated = await gnap.rotate(done.grant);
    assert.equal(rotated.accessToken, 'access-2');
    assert.equal(rotated.subject?.sub, 'user-1');
    assert.equal(rotated.continue?.uri, done.grant.continue?.uri);
    await gnap.revoke(rotated);
    assert.equal(seen.at(-1)!.method, 'DELETE');
    await assert.rejects(() => gnap.finishRedirect({ hash, interact_ref: 'ref-1' }, { allowedIds: [result.pending.id] }), /already used/);
  });

  it('proves the key with detached JWS and with mutual TLS', async () => {
    seen = [];
    behavior.tooFast = false;
    const jwsd = client('jwsd');
    const first = await started(jwsd);
    assert.equal(first.request.client.key?.proof, 'jwsd');
    const hash = finishHash(first.request.interact.finish.nonce, 'ref-j', `${base}/gnap`);
    const done = await jwsd.finishRedirect(`?hash=${hash}&interact_ref=ref-j`, { allowedIds: [first.result.pending.id] });
    assert.equal(done.grant.subject?.name, 'Ada');
    assert.equal(seen.some((call) => call.url === '/continue' && call.detached.includes('.')), true);
    assert.equal(seen.find((call) => call.url === '/continue')!.signature, '');

    seen = [];
    const mtls = client('mtls', { grantEndpoint: `${mtlsBase}/gnap`, idTokenIssuer: mtlsBase });
    const second = await started(mtls);
    assert.equal(second.request.client.key?.proof, 'mtls');
    assert.equal(seen.find((call) => call.url === '/gnap')!.cert, clientKey.certificate.fingerprint256);
    assert.equal(seen.find((call) => call.url === '/gnap')!.signature, '');
    assert.equal(seen.find((call) => call.url === '/gnap')!.detached, '');
    const hash2 = finishHash(second.request.interact.finish.nonce, 'ref-m', `${mtlsBase}/gnap`);
    const finished = await mtls.finishPush({ hash: hash2, interact_ref: 'ref-m' });
    assert.equal(finished.grant.accessToken, 'access-1');
    const answer = await mtls.call(finished.grant, `${mtlsBase}/jwks`);
    assert.equal(answer.status, 200);
    assert.match(seen.at(-1)!.authorization, /^GNAP access-1$/);

    // The mutual TLS listener refuses the handshake for a certificate the client did not register.
    const stranger = createSelfSignedKeyPair({ commonName: 'stranger' });
    const refused = client('mtls', {
      grantEndpoint: `${mtlsBase}/gnap`,
      idTokenIssuer: mtlsBase,
      privateKey: stranger.privateKeyPem,
      certificate: stranger.certificatePem,
    });
    seen = [];
    await assert.rejects(() => refused.requestGrant());
    assert.equal(seen.length, 0);
  });

  it('refuses a bearer downgrade, a bad audience, and a subject that does not match', async () => {
    behavior.bearer = true;
    const gnap = client('httpsig');
    const { result, request } = await started(gnap);
    const hash = finishHash(request.interact.finish.nonce, 'ref-b', `${base}/gnap`);
    await assert.rejects(
      () => gnap.finishRedirect({ hash, interact_ref: 'ref-b' }, { allowedIds: [result.pending.id] }),
      (err: unknown) => err instanceof GnapError && err.code === 'validation' && /bearer/.test(err.message),
    );
    behavior.bearer = false;
    behavior.aud = 'someone-else';
    const audience = client('httpsig');
    const next = await started(audience);
    const hash2 = finishHash(next.request.interact.finish.nonce, 'ref-a', `${base}/gnap`);
    await assert.rejects(
      () => audience.finishRedirect({ hash: hash2, interact_ref: 'ref-a' }, { allowedIds: [next.result.pending.id] }),
      /id_token is for/,
    );
    behavior.aud = 'gnap-caep-risc-demo';
    behavior.issSub = 'other-user';
    behavior.sub = 'user-1';
    const third = await started(gnap);
    const hash3 = finishHash(third.request.interact.finish.nonce, 'ref-s', `${base}/gnap`);
    await assert.rejects(
      () => gnap.finishRedirect({ hash: hash3, interact_ref: 'ref-s' }, { allowedIds: [third.result.pending.id] }),
      /somebody other/,
    );
    behavior.issSub = undefined;
    behavior.aud = 'instance-1';
  });

  it('accepts the application identifier as the ID token audience', async () => {
    behavior.aud = 'gnap-caep-risc-demo';
    behavior.sub = 'user-2';
    const gnap = client('httpsig');
    const { result, request } = await started(gnap);
    const hash = finishHash(request.interact.finish.nonce, 'ref-app', `${base}/gnap`);
    const done = await gnap.finishRedirect({ hash, interact_ref: 'ref-app' }, { allowedIds: [result.pending.id] });
    assert.equal(done.grant.subject?.sub, 'user-2');
    behavior.aud = 'instance-1';
    const fresh = await gnap.ensureFresh({ ...done.grant, expiresAt: Date.now() + 10_000 });
    assert.equal(fresh.accessToken, 'access-2');
    const held = await gnap.ensureFresh({ ...fresh, expiresAt: Date.now() + 3_600_000 });
    assert.equal(held.accessToken, 'access-2');
  });

  it('refuses a continuation URI that carries user information on the grant endpoint origin', async () => {
    seen = [];
    behavior.continueUri = `${base.replace('https://', 'https://user:secret@')}/continue`;
    try {
      const gnap = client('httpsig');
      await assert.rejects(() => gnap.requestGrant(), (err: unknown) => err instanceof GnapError
        && /must not carry user information/.test(err.message) && !err.message.includes('secret'));
      assert.equal(seen.filter((call) => call.url === '/continue').length, 0);
    } finally {
      delete behavior.continueUri;
    }
  });

  it('does not follow a too_fast continuation to another origin', async () => {
    seen = [];
    tooFastSent = false;
    behavior.tooFast = true;
    behavior.tooFastUri = 'https://evil.example/continue';
    try {
      const gnap = client('httpsig');
      const { result, request } = await started(gnap);
      const hash = finishHash(request.interact.finish.nonce, 'ref-f', `${base}/gnap`);
      await assert.rejects(
        () => gnap.finishRedirect({ hash, interact_ref: 'ref-f' }, { allowedIds: [result.pending.id] }),
        (err: unknown) => err instanceof GnapError && /not on the grant endpoint/.test(err.message),
      );
      assert.equal(tooFastSent, true);
      assert.equal(seen.filter((call) => call.url === '/continue').length, 1);
    } finally {
      behavior.tooFast = false;
      delete behavior.tooFastUri;
    }
  });

  it('checks the TLS certificate by default: without tlsCa a self-signed grant server is refused', async () => {
    seen = [];
    const gnap = client('httpsig', { tlsCa: undefined });
    assert.equal(Object.hasOwn(gnap.tls(), 'rejectUnauthorized'), false);
    assert.equal(Object.hasOwn(gnap.tls(), 'ca'), false);
    await assert.rejects(() => gnap.requestGrant(), (err: unknown) => err instanceof GnapError && /certificate/i.test(err.message));
    assert.equal(seen.length, 0);
  });
});

describe('a certificate chain', () => {
  it('puts the leaf in the GNAP key and the chain on the TLS handshake', () => {
    const leaf = createSelfSignedKeyPair({ commonName: 'leaf.example' });
    const issuer = createSelfSignedKeyPair({ commonName: 'issuer.example' });
    const chain = `${leaf.certificatePem.trim()}\n${issuer.certificatePem.trim()}\n`;
    const key = loadClientKey(leaf.privateKeyPem, chain, 'mtls');
    const published = publicKeyObject(key);
    assert.equal(String(published.cert).match(/BEGIN CERTIFICATE/g)?.length, 1);
    assert.equal(new X509Certificate(String(published.cert)).fingerprint256, leaf.certificate.fingerprint256);
    const gnap = GnapClient.create(GnapClient.resolve({
      grantEndpoint: 'https://as.example/gnap',
      application: 'chain-demo',
      keyProof: 'mtls',
      privateKey: leaf.privateKeyPem,
      certificate: chain,
      finishUri: 'http://127.0.0.1:9/callback',
    }, process.cwd()));
    assert.equal(gnap.tls().cert?.match(/BEGIN CERTIFICATE/g)?.length, 2);
  });
});
