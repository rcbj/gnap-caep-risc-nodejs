// The configuration file. The names that overlap gnap-caep-js's gnap.json mean the same thing:
// grantEndpoint, transmitterIssuer, idTokenIssuer, application, display, access, subIdFormats,
// assertionFormats. `application` here is the registered application's identifier. It is not sent as
// `class_id` — a server holds the private key, so the key itself is registered.
// A secret is the value, `env:NAME`, `file:path` (next to this file), or a filesystem path.

import { readFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { GnapError } from './errors.ts';
import { loadClientKey, type ClientKey, type KeyProof } from './keys.ts';

const PROOFS: readonly KeyProof[] = ['mtls', 'httpsig', 'jwsd'];

/** A configuration file, or the object {@link resolveConfig} accepts. */
export interface GnapConfigFile {
  /** The grant endpoint, `https://idp.example/gnap`. Required. */
  grantEndpoint?: string;
  /** gnap-caep-js's name for the Shared Signals transmitter. `ssf.transmitter` wins when both are set. */
  transmitterIssuer?: string;
  /** The issuer of subject ID tokens. Defaults to the grant endpoint's origin. */
  idTokenIssuer?: string;
  /**
   * The registered application's identifier. Not sent as `class_id`. Used as an ID token audience
   * and as what the setup script registers.
   */
  application?: string;
  /** Sent as `client.class_id` only when set. The demo does not set it. An unregistered instance's identifier. */
  classId?: string;
  display?: { name?: string; uri?: string };
  /** Access rights, as strings or objects. Default `ssf.read` and `ssf.manage`. */
  access?: unknown[];
  subIdFormats?: string[];
  assertionFormats?: string[];
  /** `mtls`, `httpsig`, or `jwsd`. Default `mtls` when `certificate` is set, otherwise `httpsig`. */
  keyProof?: string;
  /** PEM PKCS#8, `file:path`, `env:NAME`, or a path. Required. */
  privateKey?: string;
  /** PEM certificate. Required for `mtls`. */
  certificate?: string;
  /** Where the authorization server redirects the browser, or pushes the finish. */
  finishUri?: string;
  /** `redirect` (default) or `push`. */
  finishMethod?: string;
  /** Interaction start modes. Default `["redirect"]`. */
  interactionStart?: string[];
  /** Interaction hash. Only `sha-256`, the default, and it is omitted from the request. */
  hashMethod?: string;
  /** Refuse a token whose flags include `bearer`. Default true. */
  requireBoundTokens?: boolean;
  /** After the first response, send `client` as the `instance_id` string. Default true. */
  useInstanceId?: boolean;
  /**
   * PEM certificates to trust for the authorization server: the PEM itself, `file:path`, `env:NAME`,
   * or a path. A missing file is ignored, so a demo can name a CA the setup script has not written yet.
   */
  tlsCa?: string;
  /** Allow an `http` grant endpoint, and a non-loopback `http` finish URI. Default false. */
  allowInsecure?: boolean;
  clockToleranceSec?: number;
  /** The longest a `continue.wait` or a `too_fast` retry may delay one continuation. Default 30. */
  maxWaitSec?: number;
  /** How long a pending interaction may sit. Default 600. */
  transactionTtlSec?: number;
  ssf?: { transmitter?: string; pollIntervalMs?: number };
}

/** Configuration after paths and the key have been read. */
export interface ResolvedConfig {
  grantEndpoint: string;
  idTokenIssuer: string;
  application: string;
  classId?: string;
  display?: { name?: string; uri?: string };
  access: unknown[];
  subIdFormats: string[];
  assertionFormats: string[];
  key: ClientKey;
  finishUri?: string;
  finishMethod: 'redirect' | 'push';
  interactionStart: string[];
  hashMethod: 'sha-256';
  requireBoundTokens: boolean;
  useInstanceId: boolean;
  tlsCa?: string;
  allowInsecure: boolean;
  clockToleranceSec: number;
  maxWaitSec: number;
  transactionTtlSec: number;
  ssf?: { transmitter: string; pollIntervalMs?: number };
}

function asObject(raw: unknown): GnapConfigFile {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new GnapError('config', 'the configuration must be a JSON object');
  return raw as GnapConfigFile;
}

function readPath(path: string, baseDir: string, what: string): string {
  const full = isAbsolute(path) ? path : resolve(baseDir, path);
  try {
    return readFileSync(full, 'utf8');
  } catch (err) {
    throw new GnapError('config', `could not read ${what} at ${full}: ${(err as Error).message}`, { cause: err });
  }
}

function secretValue(raw: string, baseDir: string, what: string): string {
  if (raw.startsWith('env:')) {
    const name = raw.slice(4);
    const value = process.env[name];
    if (!value) throw new GnapError('config', `${what} reads ${name}, and that variable is empty`);
    return value;
  }
  if (raw.startsWith('file:')) return readPath(raw.slice(5), baseDir, what);
  return raw;
}

function keyValue(raw: string, baseDir: string, what: string): string {
  if (raw.startsWith('env:') || raw.startsWith('file:') || raw.includes('-----BEGIN')) return secretValue(raw, baseDir, what);
  return readPath(raw, baseDir, what);
}

/** A trust bundle is PEM, `file:`, `env:`, or a path. A path that is not there yet is absent, not an error. */
function readTrust(raw: string | undefined, baseDir: string): string | undefined {
  if (!raw) return undefined;
  if (raw.includes('-----BEGIN')) return raw;
  if (raw.startsWith('env:')) return process.env[raw.slice(4)] || undefined;
  const path = raw.startsWith('file:') ? raw.slice(5) : raw;
  const full = isAbsolute(path) ? path : resolve(baseDir, path);
  try {
    return readFileSync(full, 'utf8');
  } catch {
    return undefined;
  }
}

export function isLoopback(url: URL): boolean {
  return url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
}

function checkUrl(value: string, name: string, allowHttp: boolean): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new GnapError('config', `${name} is not a URL: ${value}`);
  }
  if (url.protocol === 'https:') return url.href;
  if (url.protocol === 'http:' && allowHttp) return url.href;
  throw new GnapError('config', `${name} must use https${allowHttp ? '' : ', or http on loopback'}: ${value}`);
}

/**
 * Reads a configuration object: resolves `file:` and `env:` secrets, loads the key, and fills the
 * defaults. `baseDir` is where relative paths start. Nothing is fetched.
 */
export function resolveConfig(raw: unknown, baseDir: string): ResolvedConfig {
  const doc = asObject(raw);
  const application = String(doc.application ?? '').trim();
  if (!application) throw new GnapError('config', 'application is required: the registered GNAP client');
  const grantRaw = String(doc.grantEndpoint ?? '').trim();
  if (!grantRaw) throw new GnapError('config', 'grantEndpoint is required');
  const allowInsecure = doc.allowInsecure === true;
  const grantEndpoint = checkUrl(grantRaw, 'grantEndpoint', allowInsecure);
  const origin = new URL(grantEndpoint).origin;
  const idTokenIssuer = (doc.idTokenIssuer?.trim() || origin).replace(/\/+$/, '');
  if (!/^https?:\/\//.test(idTokenIssuer)) throw new GnapError('config', 'idTokenIssuer must be an http(s) URL');

  const proofRaw = doc.keyProof?.trim();
  if (proofRaw && !PROOFS.includes(proofRaw as KeyProof)) {
    throw new GnapError('config', `keyProof must be ${PROOFS.join(', ')}, not ${proofRaw}`);
  }
  if (!doc.privateKey) throw new GnapError('config', 'privateKey is required');
  const privateKeyPem = keyValue(doc.privateKey, baseDir, 'the private key');
  const certificatePem = doc.certificate ? keyValue(doc.certificate, baseDir, 'the certificate') : undefined;
  const key = loadClientKey(privateKeyPem, certificatePem, proofRaw as KeyProof | undefined);
  if (key.proof === 'mtls' && new URL(grantEndpoint).protocol !== 'https:') {
    throw new GnapError('config', 'mutual TLS needs an https grant endpoint');
  }

  const finishMethodRaw = doc.finishMethod ?? 'redirect';
  if (finishMethodRaw !== 'redirect' && finishMethodRaw !== 'push') {
    throw new GnapError('config', 'finishMethod must be redirect or push');
  }
  const finishUriRaw = String(doc.finishUri ?? '').trim();
  let finishLoopback = false;
  if (finishUriRaw) {
    try {
      finishLoopback = isLoopback(new URL(finishUriRaw));
    } catch {
      finishLoopback = false;
    }
  }
  const finishUri = finishUriRaw ? checkUrl(finishUriRaw, 'finishUri', allowInsecure || finishLoopback) : undefined;
  const hashMethod = doc.hashMethod ?? 'sha-256';
  if (hashMethod !== 'sha-256') throw new GnapError('config', 'hashMethod must be sha-256');
  const interactionStart = doc.interactionStart ?? ['redirect'];
  if (!interactionStart.length || interactionStart.some((mode) => !mode)) {
    throw new GnapError('config', 'interactionStart must name at least one mode');
  }

  const access = doc.access ?? ['ssf.read', 'ssf.manage'];
  if (!Array.isArray(access) || !access.length) throw new GnapError('config', 'access must list at least one right');

  const tlsCa = readTrust(doc.tlsCa, baseDir);

  const transmitter = (doc.ssf?.transmitter ?? doc.transmitterIssuer)?.replace(/\/+$/, '');
  let ssf: ResolvedConfig['ssf'];
  if (transmitter) {
    if (!/^https?:\/\//.test(transmitter)) throw new GnapError('config', 'ssf.transmitter must be an http(s) URL');
    ssf = { transmitter, ...(doc.ssf?.pollIntervalMs ? { pollIntervalMs: doc.ssf.pollIntervalMs } : {}) };
  }

  const display = doc.display && (doc.display.name || doc.display.uri)
    ? { ...(doc.display.name ? { name: doc.display.name } : {}), ...(doc.display.uri ? { uri: doc.display.uri } : {}) }
    : undefined;

  return {
    grantEndpoint,
    idTokenIssuer,
    application,
    ...(doc.classId ? { classId: doc.classId } : {}),
    ...(display ? { display } : {}),
    access,
    subIdFormats: doc.subIdFormats ?? ['iss_sub', 'account', 'opaque'],
    assertionFormats: doc.assertionFormats ?? ['id_token'],
    key,
    ...(finishUri ? { finishUri } : {}),
    finishMethod: finishMethodRaw,
    interactionStart,
    hashMethod: 'sha-256',
    requireBoundTokens: doc.requireBoundTokens !== false,
    useInstanceId: doc.useInstanceId !== false,
    ...(tlsCa ? { tlsCa } : {}),
    allowInsecure,
    clockToleranceSec: doc.clockToleranceSec ?? 30,
    maxWaitSec: doc.maxWaitSec ?? 30,
    transactionTtlSec: doc.transactionTtlSec ?? 600,
    ...(ssf ? { ssf } : {}),
  };
}

/** Reads a configuration file and resolves it. Relative paths start in the file's directory. */
export function readConfigFile(path: string): ResolvedConfig {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new GnapError('config', `could not read ${path}: ${(err as Error).message}`, { cause: err });
  }
  return resolveConfig(raw, resolve(path, '..'));
}
