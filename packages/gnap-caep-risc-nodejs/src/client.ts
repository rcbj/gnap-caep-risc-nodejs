// A server-side GNAP client (RFC 9635). The private key stays here. The browser is sent to
// `interact.redirect` and comes back with a hash and an `interact_ref`; the continuation token, the
// access token and the management token are never in that redirect.
//
// The key is registered, not a per-browser `class_id`. It is proved by mutual TLS, an HTTP message
// signature, or a detached JWS — whichever `keyProof` names. Tokens are key-bound: a `bearer` flag is
// refused. A `continue` or `manage` URI on another origin is refused before anything is sent there.

import { randomBytes } from 'node:crypto';
import { discoverGrantServer, discoverOpenId, type GrantServerMetadata } from './discovery.ts';
import { GnapError, type ErrorContinuation } from './errors.ts';
import { hashEqual, interactionHash } from './hash.ts';
import { send, type HttpAnswer, type TlsOptions } from './http.ts';
import { signRequest } from './httpsig.ts';
import { detachedJws } from './jwsd.ts';
import { publicKeyObject, type ClientKey } from './keys.ts';
import { readConfigFile, resolveConfig, isLoopback, type ResolvedConfig } from './config.ts';
import { personFrom, type Person } from './subject.ts';
import type { Jwk } from './ssf/jws.ts';

const FRONT_CHANNEL = ['access_token', 'id_token', 'token', 'value', 'continue', 'refresh_token'];

/** A continuation or management handle. The token is presented as `Authorization: GNAP`. */
export interface Continuation {
  uri: string;
  accessToken: string;
  /** Seconds the authorization server asked the client to wait before calling `uri`. */
  wait?: number;
}

/** One issued access token and the grant it belongs to. */
export interface Grant {
  accessToken: string;
  /** When the token expires, epoch milliseconds. Absent when the server named no `expires_in`. */
  expiresAt?: number;
  expiresIn?: number;
  /** True only when the server set the `bearer` flag. This client refuses that while bound tokens are required. */
  bearer: boolean;
  access: unknown;
  manage?: Continuation;
  continue?: Continuation;
  instanceId?: string;
  subject?: Person;
  /** The last path segment of the continuation URI, when there is one. */
  grantId?: string;
}

/** An interaction the browser has been sent to finish. Kept in this process, named by `id`. */
export interface PendingGrant {
  id: string;
  clientNonce: string;
  serverNonce: string;
  hashMethod: 'sha-256';
  continue: Continuation;
  /** Epoch milliseconds before which the continuation is not called. */
  continueNotBefore: number;
  grantEndpoint: string;
  createdAt: number;
  context?: unknown;
  instanceId?: string;
  expectedSub?: string;
}

export interface GrantRequestOptions {
  /** Access rights. Default: the configuration's `access`. */
  access?: unknown[];
  /** A hint of who the user is, sent as `user` (RFC 9635 section 2.4). */
  user?: unknown;
  /** Refuse the grant when the subject is somebody else. */
  expectedSub?: string;
  /** Handed back by {@link GnapClient.finishRedirect}. Must be JSON-serialisable. */
  context?: unknown;
  /** `false` asks for no subject information. */
  subject?: boolean;
}

export interface FinishedGrant {
  grant: Grant;
  context?: unknown;
}

/** What this client refuses to do without, so a caller can show it. */
export interface SecurityPosture {
  keyProof: ClientKey['proof'];
  boundTokens: boolean;
  finishMethod: 'redirect' | 'push';
  interactionHash: true;
  registeredKey: true;
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function grantIdOf(uri: string | undefined): string | undefined {
  if (!uri) return undefined;
  try {
    const last = new URL(uri).pathname.split('/').filter(Boolean).pop();
    return last ? decodeURIComponent(last) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The GNAP client. {@link GnapClient.fromFile} loads the key and does not contact the authorization
 * server; discovery happens on the first grant.
 */
export class GnapClient {
  readonly config: ResolvedConfig;
  #metadata: GrantServerMetadata | undefined;
  #instanceId: string | undefined;
  #subIdFormats: string[];
  #assertionFormats: string[];
  #jwks: Jwk[] | undefined;
  readonly #pending = new Map<string, PendingGrant>();
  readonly #used = new Set<string>();

  private constructor(config: ResolvedConfig) {
    this.config = config;
    this.#subIdFormats = [...config.subIdFormats];
    this.#assertionFormats = [...config.assertionFormats];
  }

  /** Loads `path` and the key it names. Does not discover. */
  static fromFile(path: string): GnapClient {
    return new GnapClient(readConfigFile(path));
  }

  /** A client for an already-resolved configuration. */
  static create(config: ResolvedConfig): GnapClient {
    return new GnapClient(config);
  }

  /** Resolves a configuration object. Relative paths start at `baseDir`. */
  static resolve(raw: unknown, baseDir: string): ResolvedConfig {
    return resolveConfig(raw, baseDir);
  }

  /** The loaded key. The private half is on it; do not send that anywhere. */
  get key(): ClientKey {
    return this.config.key;
  }

  /** How this client proves itself. */
  get security(): SecurityPosture {
    return {
      keyProof: this.config.key.proof,
      boundTokens: this.config.requireBoundTokens,
      finishMethod: this.config.finishMethod,
      interactionHash: true,
      registeredKey: true,
    };
  }

  /** The instance identifier from the first response, once the server has issued one. */
  get instanceId(): string | undefined {
    return this.#instanceId;
  }

  /** TLS for every call to the authorization server and, for mutual TLS, the client certificate. */
  tls(): TlsOptions {
    return {
      ...(this.config.tlsCa ? { ca: this.config.tlsCa } : {}),
      ...(this.config.key.proof === 'mtls' && this.config.key.certificatePem
        ? { cert: this.config.key.certificatePem, key: this.config.key.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string }
        : {}),
    };
  }

  /** OPTIONS on the grant endpoint. Repeated calls reuse the first answer. */
  async discover(): Promise<GrantServerMetadata> {
    if (this.#metadata) return this.#metadata;
    const metadata = await discoverGrantServer(this.config.grantEndpoint, this.tls());
    const proofs = metadata.key_proofs_supported;
    if (proofs && !proofs.includes(this.config.key.proof)) {
      throw new GnapError('discovery', `the grant server does not accept the ${this.config.key.proof} key proof`);
    }
    const finishes = metadata.interaction_finish_methods_supported;
    if (finishes && this.config.finishUri && !finishes.includes(this.config.finishMethod)) {
      throw new GnapError('discovery', `the grant server does not accept a ${this.config.finishMethod} interaction finish`);
    }
    if (metadata.sub_id_formats_supported) {
      this.#subIdFormats = this.#subIdFormats.filter((format) => metadata.sub_id_formats_supported!.includes(format));
    }
    if (metadata.assertion_formats_supported) {
      this.#assertionFormats = this.#assertionFormats.filter((format) => metadata.assertion_formats_supported!.includes(format));
    }
    this.#metadata = metadata;
    return metadata;
  }

  /**
   * Starts a grant. When the server needs the person, the result has `redirectUrl` and `pending`:
   * send the browser to the URL, and keep `pending.id` (not the continuation token) until
   * {@link GnapClient.finishRedirect}. When the server issues the token at once, the result has `grant`.
   */
  async requestGrant(options: GrantRequestOptions = {}): Promise<{ redirectUrl: string; pending: PendingGrant } | { grant: Grant }> {
    await this.discover();
    const access = options.access ?? this.config.access;
    if (!Array.isArray(access) || !access.length) throw new GnapError('config', 'access is required');
    const clientNonce = randomBytes(24).toString('base64url');
    const body: Record<string, unknown> = {
      access_token: { access },
      client: this.#clientMember(),
    };
    if (this.config.finishUri) {
      body.interact = {
        start: this.config.interactionStart,
        finish: {
          method: this.config.finishMethod,
          uri: this.config.finishUri,
          nonce: clientNonce,
        },
      };
    }
    if (options.subject !== false && (this.#subIdFormats.length || this.#assertionFormats.length)) {
      body.subject = {
        ...(this.#subIdFormats.length ? { sub_id_formats: this.#subIdFormats } : {}),
        ...(this.#assertionFormats.length ? { assertion_formats: this.#assertionFormats } : {}),
      };
    }
    if (options.user !== undefined) body.user = options.user;
    const answer = await this.#signedJson('POST', this.config.grantEndpoint, { body });
    this.#rememberInstance(answer);
    if (answer && typeof answer === 'object' && 'interact' in answer && answer.interact) {
      return { redirectUrl: this.#redirect(answer), pending: this.#rememberPending(answer, clientNonce, options) };
    }
    if (this.#hasToken(answer)) {
      const grant = await this.#grantFrom(answer, {});
      this.#expect(grant, options.expectedSub);
      return { grant };
    }
    throw new GnapError('protocol', 'the grant response has neither an interaction nor an access token');
  }

  /**
   * Completes a redirect finish. `allowedIds` are the pending grants this browser started: a redirect
   * URL stolen from one browser does not finish in another. The hash is single use.
   */
  async finishRedirect(query: URLSearchParams | string | Record<string, string>, options: { allowedIds: readonly string[] }): Promise<FinishedGrant> {
    const params = toParams(query);
    const injected = FRONT_CHANNEL.filter((name) => params.has(name));
    if (injected.length) throw new GnapError('validation', `the finish redirect carries ${injected.join(', ')}; GNAP does not send tokens through the browser`);
    for (const name of new Set(params.keys())) {
      if (params.getAll(name).length > 1) throw new GnapError('validation', `the finish redirect repeats "${name}"`);
    }
    const hash = params.get('hash');
    const interactRef = params.get('interact_ref');
    if (!hash || !interactRef) {
      if (params.get('error')) {
        throw new GnapError('protocol', params.get('error_description') || params.get('error') || 'the interaction failed', { gnapError: params.get('error') ?? undefined });
      }
      throw new GnapError('validation', 'the finish redirect has no hash or interact_ref');
    }
    const pending = this.#match(hash, interactRef, options.allowedIds);
    return this.#finish(pending, interactRef, hash);
  }

  /**
   * Completes a push finish. The authorization server posts `{ hash, interact_ref }` to `finishUri`;
   * there is no browser cookie, and the hash is what authenticates the call.
   */
  async finishPush(body: unknown): Promise<FinishedGrant> {
    if (!body || typeof body !== 'object') throw new GnapError('validation', 'a push finish is a JSON object');
    const doc = body as { hash?: unknown; interact_ref?: unknown; error?: unknown };
    if (typeof doc.hash !== 'string' || typeof doc.interact_ref !== 'string') {
      if (typeof doc.error === 'string') throw new GnapError('protocol', doc.error, { gnapError: doc.error });
      throw new GnapError('validation', 'a push finish needs hash and interact_ref');
    }
    const pending = this.#match(doc.hash, doc.interact_ref);
    return this.#finish(pending, doc.interact_ref, doc.hash);
  }

  /**
   * Headers for one request that presents `grant`'s access token: `Authorization: GNAP`, and the key
   * proof. Pass the exact body that will be sent. Mutual TLS adds no signature header; the certificate
   * is on the connection from {@link GnapClient.tls}.
   */
  authorizationHeaders(grant: Grant, request: { method: string; url: string; body?: string; headers?: Record<string, string> }): Record<string, string> {
    return this.#proofHeaders(request.method, request.url, request.body, grant.accessToken, request.headers);
  }

  /** Sends `url` with the access token and the key proof. */
  async call(grant: Grant, url: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<HttpAnswer> {
    const method = init.method ?? 'GET';
    const headers = this.authorizationHeaders(grant, { method, url, ...(init.body !== undefined ? { body: init.body } : {}), ...(init.headers ? { headers: init.headers } : {}) });
    return send(url, { method, headers: { ...(init.headers ?? {}), ...headers }, ...(init.body !== undefined ? { body: init.body } : {}) }, this.tls(), 'protocol');
  }

  /** Rotates the access token (RFC 9635 section 6.1). The continuation and the subject carry over. */
  async rotate(grant: Grant): Promise<Grant> {
    if (!grant.manage) throw new GnapError('protocol', 'this access token has no manage URI');
    this.#checkSameOrigin(grant.manage.uri, 'manage.uri');
    const answer = await this.#signedJson('POST', grant.manage.uri, { token: grant.manage.accessToken });
    if (!this.#hasToken(answer)) throw new GnapError('protocol', 'the rotation returned no access token');
    const next = await this.#grantFrom(answer, { previous: grant });
    if (!grant.bearer && next.bearer) throw new GnapError('validation', 'rotating a key-bound token returned a bearer token');
    return next;
  }

  /** Revokes the whole grant (RFC 9635 section 5.4). A 204 is success. */
  async revoke(grant: Grant): Promise<void> {
    if (!grant.continue) throw new GnapError('protocol', 'this grant has no continuation, so it cannot be revoked');
    this.#checkSameOrigin(grant.continue.uri, 'continue.uri');
    await this.#signedJson('DELETE', grant.continue.uri, { token: grant.continue.accessToken });
  }

  /** Rotates the access token when it expires within 60 seconds, or already has. */
  async ensureFresh(grant: Grant, now = Date.now()): Promise<Grant> {
    if (grant.expiresAt === undefined || grant.expiresAt - now > 60_000) return grant;
    return this.rotate(grant);
  }

  #clientMember(): unknown {
    if (this.config.useInstanceId && this.#instanceId) return this.#instanceId;
    return {
      key: publicKeyObject(this.config.key),
      ...(this.config.display ? { display: this.config.display } : {}),
      ...(this.config.classId ? { class_id: this.config.classId } : {}),
    };
  }

  #rememberInstance(answer: unknown): void {
    if (!this.config.useInstanceId || !answer || typeof answer !== 'object') return;
    const id = (answer as { instance_id?: unknown }).instance_id;
    if (typeof id === 'string' && id) this.#instanceId = id;
  }

  #redirect(answer: object): string {
    const interact = (answer as { interact?: { redirect?: unknown } }).interact;
    const redirect = interact?.redirect;
    if (typeof redirect !== 'string') throw new GnapError('protocol', 'the interaction is not a redirect');
    let url: URL;
    try {
      url = new URL(redirect);
    } catch {
      throw new GnapError('protocol', `interact.redirect is not a URL: ${redirect}`);
    }
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && (this.config.allowInsecure || isLoopback(url)))) {
      throw new GnapError('validation', `interact.redirect must use https: ${redirect}`);
    }
    return redirect;
  }

  #rememberPending(answer: object, clientNonce: string, options: GrantRequestOptions): PendingGrant {
    const interact = (answer as { interact?: { finish?: unknown } }).interact;
    if (typeof interact?.finish !== 'string' || !interact.finish) {
      throw new GnapError('protocol', 'the grant response has no interaction finish nonce');
    }
    const cont = this.#continuation((answer as { continue?: unknown }).continue, 'continue');
    const waitMs = (cont.wait ?? 0) * 1000;
    const pending: PendingGrant = {
      id: clientNonce,
      clientNonce,
      serverNonce: interact.finish,
      hashMethod: 'sha-256',
      continue: cont,
      continueNotBefore: Date.now() + waitMs,
      grantEndpoint: this.config.grantEndpoint,
      createdAt: Date.now(),
      ...(options.context !== undefined ? { context: options.context } : {}),
      ...(this.#instanceId ? { instanceId: this.#instanceId } : {}),
      ...(options.expectedSub ? { expectedSub: options.expectedSub } : {}),
    };
    this.#sweep();
    this.#pending.set(pending.id, pending);
    return pending;
  }

  #match(hash: string, interactRef: string, allowedIds?: readonly string[]): PendingGrant {
    if (this.#used.has(hash)) throw new GnapError('validation', 'this interaction finish was already used');
    for (const pending of this.#pending.values()) {
      if (allowedIds && !allowedIds.includes(pending.id)) continue;
      const expected = interactionHash(pending.clientNonce, pending.serverNonce, interactRef, pending.grantEndpoint);
      if (!hashEqual(hash, expected)) continue;
      if (Date.now() - pending.createdAt > this.config.transactionTtlSec * 1000) {
        this.#pending.delete(pending.id);
        throw new GnapError('validation', 'the approval took too long; start again', { context: pending.context });
      }
      return pending;
    }
    throw new GnapError('validation', allowedIds
      ? 'this finish is not a sign-in this browser started'
      : 'the interaction hash matches no grant in progress');
  }

  async #finish(pending: PendingGrant, interactRef: string, hash: string): Promise<FinishedGrant> {
    this.#pending.delete(pending.id);
    this.#used.add(hash);
    if (this.#used.size > 1000) this.#used.delete(this.#used.values().next().value!);
    const due = pending.continueNotBefore - Date.now();
    if (due > 0) await sleep(Math.min(due, this.config.maxWaitSec * 1000));
    let answer: unknown;
    try {
      answer = await this.#continue(pending.continue, { interact_ref: interactRef });
    } catch (err) {
      if (err instanceof GnapError) err.context = pending.context;
      throw err;
    }
    if (!this.#hasToken(answer)) {
      const error = new GnapError('protocol', 'the resource owner did not approve the grant', { gnapError: 'user_denied', context: pending.context });
      throw error;
    }
    try {
      const grant = await this.#grantFrom(answer, { previousContinue: pending.continue });
      this.#expect(grant, pending.expectedSub);
      return { grant, ...(pending.context !== undefined ? { context: pending.context } : {}) };
    } catch (err) {
      if (err instanceof GnapError) err.context = pending.context;
      throw err;
    }
  }

  async #continue(cont: Continuation, body: unknown): Promise<unknown> {
    let current = cont;
    let waited = 0;
    let immediate = 0;
    for (;;) {
      try {
        return await this.#signedJson('POST', current.uri, { body, token: current.accessToken });
      } catch (err) {
        if (!(err instanceof GnapError) || err.gnapError !== 'too_fast') throw err;
        if (err.continuation) {
          this.#checkSameOrigin(err.continuation.uri, 'continue.uri');
          current = { uri: err.continuation.uri, accessToken: err.continuation.accessToken, ...(err.continuation.wait !== undefined ? { wait: err.continuation.wait } : {}) };
        }
        const wait = Math.max(0, Number(current.wait ?? 0));
        if (wait === 0) {
          immediate += 1;
          if (immediate > 2) throw err;
          continue;
        }
        if (waited + wait > this.config.maxWaitSec) throw err;
        await sleep(wait * 1000);
        waited += wait;
      }
    }
  }

  async #signedJson(method: string, url: string, options: { body?: unknown; token?: string }): Promise<unknown> {
    this.#checkSameOrigin(url, 'the request URL');
    const text = options.body === undefined ? undefined : JSON.stringify(options.body);
    const headers = this.#proofHeaders(method, url, text, options.token, text !== undefined ? { 'content-type': 'application/json' } : undefined);
    headers.accept = 'application/json';
    const answer = await send(url, { method, headers, ...(text !== undefined ? { body: text } : {}) }, this.tls(), 'protocol');
    return this.#read(answer);
  }

  #proofHeaders(method: string, url: string, body: string | undefined, token: string | undefined, extra?: Record<string, string>): Record<string, string> {
    const headers: Record<string, string> = { ...(extra ?? {}) };
    if (token) headers.authorization = `GNAP ${token}`;
    if (this.config.key.proof === 'httpsig') {
      const signed = signRequest(this.config.key, { method, url, headers, ...(body !== undefined ? { body } : {}) });
      Object.assign(headers, signed);
    } else if (this.config.key.proof === 'jwsd') {
      headers['detached-jws'] = detachedJws(this.config.key, { method, url, ...(body !== undefined ? { body } : {}), ...(token ? { token } : {}) });
    }
    return headers;
  }

  #read(answer: HttpAnswer): unknown {
    if (answer.status === 204 || !answer.body) {
      if (answer.status >= 400) throw new GnapError('protocol', `the authorization server answered ${answer.status}`);
      return undefined;
    }
    let json: unknown;
    try {
      json = JSON.parse(answer.body);
    } catch (err) {
      throw new GnapError('protocol', `the authorization server answered ${answer.status} with a body that is not JSON`, { cause: err });
    }
    if (answer.status >= 200 && answer.status < 300) return json;
    const doc = json && typeof json === 'object' ? json as { error?: unknown; error_description?: unknown; continue?: unknown } : {};
    const code = typeof doc.error === 'string' ? doc.error : undefined;
    let continuation: ErrorContinuation | undefined;
    if (doc.continue && typeof doc.continue === 'object') {
      const cont = doc.continue as { uri?: unknown; wait?: unknown; access_token?: { value?: unknown } };
      if (typeof cont.uri === 'string' && typeof cont.access_token?.value === 'string') {
        continuation = {
          uri: cont.uri,
          accessToken: cont.access_token.value,
          ...(typeof cont.wait === 'number' ? { wait: cont.wait } : {}),
        };
      }
    }
    throw new GnapError('protocol', (typeof doc.error_description === 'string' && doc.error_description) || code || `the authorization server answered ${answer.status}`, {
      ...(code ? { gnapError: code } : {}),
      ...(continuation ? { continuation } : {}),
    });
  }

  #hasToken(answer: unknown): boolean {
    return !!answer && typeof answer === 'object' && 'access_token' in answer && !!(answer as { access_token?: unknown }).access_token;
  }

  async #grantFrom(answer: unknown, previous: { previous?: Grant; previousContinue?: Continuation }): Promise<Grant> {
    const doc = answer as { access_token?: unknown; continue?: unknown; instance_id?: unknown; subject?: unknown };
    const token = Array.isArray(doc.access_token) ? doc.access_token[0] : doc.access_token;
    if (!token || typeof token !== 'object') throw new GnapError('protocol', 'the access token is not an object');
    const at = token as { value?: unknown; flags?: unknown; access?: unknown; expires_in?: unknown; manage?: unknown };
    if (typeof at.value !== 'string' || !at.value) throw new GnapError('protocol', 'the access token has no value');
    const flags = Array.isArray(at.flags) ? at.flags.map(String) : [];
    const bearer = flags.includes('bearer');
    if (bearer && this.config.requireBoundTokens) throw new GnapError('validation', 'the authorization server issued a bearer token, and this client requires a key-bound one');
    this.#rememberInstance(answer);
    let manage: Continuation | undefined;
    if (at.manage && typeof at.manage === 'object') {
      const raw = at.manage as { uri?: unknown; access_token?: { value?: unknown } };
      if (typeof raw.uri !== 'string' || typeof raw.access_token?.value !== 'string') {
        throw new GnapError('protocol', 'the access token manage object is not usable');
      }
      this.#checkSameOrigin(raw.uri, 'manage.uri');
      manage = { uri: raw.uri, accessToken: raw.access_token.value };
    } else if (previous.previous?.manage) manage = previous.previous.manage;
    let cont: Continuation | undefined;
    if (doc.continue) cont = this.#continuation(doc.continue, 'continue');
    else if (previous.previousContinue) cont = previous.previousContinue;
    else if (previous.previous?.continue) cont = previous.previous.continue;
    const audiences = [this.#instanceId, this.config.application].filter((one): one is string => !!one);
    const subject = doc.subject
      ? await personFrom(doc.subject, {
        idTokenIssuer: this.config.idTokenIssuer,
        audiences,
        clockToleranceSec: this.config.clockToleranceSec,
        keys: () => this.#idTokenKeys(),
      })
      : previous.previous?.subject;
    const expiresIn = typeof at.expires_in === 'number' ? at.expires_in : undefined;
    return {
      accessToken: at.value,
      bearer,
      access: at.access,
      ...(expiresIn !== undefined ? { expiresIn, expiresAt: Date.now() + expiresIn * 1000 } : {}),
      ...(manage ? { manage } : {}),
      ...(cont ? { continue: cont } : {}),
      ...(this.#instanceId ? { instanceId: this.#instanceId } : {}),
      ...(subject ? { subject } : {}),
      ...(grantIdOf(cont?.uri) ? { grantId: grantIdOf(cont?.uri) } : {}),
    };
  }

  #expect(grant: Grant, expectedSub: string | undefined): void {
    if (expectedSub && grant.subject && grant.subject.sub !== expectedSub) {
      throw new GnapError('validation', 'the grant was approved by somebody other than the account that was asked for');
    }
  }

  #continuation(raw: unknown, what: string): Continuation {
    if (!raw || typeof raw !== 'object') throw new GnapError('protocol', `the response has no ${what} object`);
    const cont = raw as { uri?: unknown; wait?: unknown; access_token?: { value?: unknown } };
    if (typeof cont.uri !== 'string' || typeof cont.access_token?.value !== 'string') {
      throw new GnapError('protocol', `the response has no usable ${what} object`);
    }
    this.#checkSameOrigin(cont.uri, `${what}.uri`);
    if (cont.wait !== undefined && !(typeof cont.wait === 'number' && cont.wait >= 0)) {
      throw new GnapError('protocol', `${what}.wait is not a number of seconds`);
    }
    return { uri: cont.uri, accessToken: cont.access_token.value, ...(typeof cont.wait === 'number' ? { wait: cont.wait } : {}) };
  }

  #checkSameOrigin(uri: string, what: string): void {
    let url: URL;
    try {
      url = new URL(uri);
    } catch {
      throw new GnapError('validation', `${what} is not a URL: ${uri}`);
    }
    if (url.protocol !== 'https:' && !this.config.allowInsecure) throw new GnapError('validation', `${what} must use https: ${uri}`);
    if (url.origin !== new URL(this.config.grantEndpoint).origin) {
      throw new GnapError('validation', `${what} ${uri} is not on the grant endpoint's origin`);
    }
  }

  async #idTokenKeys(): Promise<Jwk[]> {
    if (this.#jwks) return this.#jwks;
    const metadata = await discoverOpenId(this.config.idTokenIssuer, this.tls());
    const answer = await send(metadata.jwks_uri, { headers: { accept: 'application/json' } }, this.tls(), 'discovery');
    let json: { keys?: Jwk[] };
    try {
      json = JSON.parse(answer.body) as { keys?: Jwk[] };
    } catch (err) {
      throw new GnapError('discovery', 'the issuer JWKS is not JSON', { cause: err });
    }
    if (answer.status !== 200 || !Array.isArray(json.keys)) throw new GnapError('discovery', `the issuer JWKS answered ${answer.status}`);
    this.#jwks = json.keys;
    return json.keys;
  }

  #sweep(): void {
    const cutoff = Date.now() - this.config.transactionTtlSec * 1000;
    for (const [id, pending] of this.#pending) if (pending.createdAt < cutoff) this.#pending.delete(id);
    while (this.#pending.size > 1000) {
      const oldest = this.#pending.keys().next().value;
      if (oldest === undefined) break;
      this.#pending.delete(oldest);
    }
  }
}

function toParams(input: URLSearchParams | string | Record<string, string>): URLSearchParams {
  if (input instanceof URLSearchParams) return input;
  if (typeof input === 'string') {
    if (/^[a-z][a-z0-9+.-]*:/i.test(input) || input.startsWith('/')) {
      const url = new URL(input, 'http://localhost');
      return url.searchParams;
    }
    return new URLSearchParams(input.replace(/^[?#]/, ''));
  }
  return new URLSearchParams(Object.entries(input).filter((entry): entry is [string, string] => typeof entry[1] === 'string'));
}
