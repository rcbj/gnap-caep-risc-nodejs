// HTTP message signatures (RFC 9421) with an RFC 9530 Content-Digest, as RFC 9635 section 7.3.1
// profiles them for GNAP's `httpsig` key proof. The same shape as gnap-caep-js, with node:crypto.
// There is no `alg` parameter: the verifier knows the key. ECDSA signatures are raw R||S.

import { createHash, randomBytes } from 'node:crypto';
import type { ClientKey } from './keys.ts';
import { signRaw } from './keys.ts';

/** Standard base64 with padding, as an RFC 8941 byte sequence uses. */
export function standardBase64(bytes: Buffer): string {
  return bytes.toString('base64');
}

/** RFC 9530: `sha-256=:<base64 of SHA-256 over the content>:`. */
export function contentDigest(body: string | Buffer): string {
  const bytes = typeof body === 'string' ? Buffer.from(body, 'utf8') : body;
  return `sha-256=:${standardBase64(createHash('sha256').update(bytes).digest())}:`;
}

function sfString(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/** The `@signature-params` value: covered components, then created, nonce, keyid and the `gnap` tag. */
export function signatureParams(components: readonly string[], params: { created: number; nonce: string; keyid: string }): string {
  let out = `(${components.map((c) => `"${c}"`).join(' ')})`;
  out += `;created=${params.created}`;
  out += `;nonce=${sfString(params.nonce)}`;
  out += `;keyid=${sfString(params.keyid)}`;
  out += ';tag="gnap"';
  return out;
}

/**
 * The RFC 9421 section 2.5 signature base. `headers` uses lower-case names. Derived components are
 * `@method` and `@target-uri`; everything else is a header value, trimmed.
 */
export function signatureBase(components: readonly string[], message: { method: string; url: string; headers: Record<string, string> }, serialisedParams: string): string {
  const lines = components.map((component) => {
    let value: string;
    if (component === '@method') value = message.method.toUpperCase();
    else if (component === '@target-uri') value = message.url;
    else {
      const header = message.headers[component];
      if (header === undefined) throw new TypeError(`Cannot sign "${component}": the request has no such header`);
      value = header.trim();
    }
    if (/[\r\n]/.test(value)) throw new TypeError(`Cannot sign "${component}": the value contains a line break`);
    return `"${component}": ${value}`;
  });
  lines.push(`"@signature-params": ${serialisedParams}`);
  return lines.join('\n');
}

export interface SignedHeaders {
  signature: string;
  'signature-input': string;
  'content-digest'?: string;
}

/**
 * Signs one request. The signature covers `@method`, `@target-uri`, `content-digest` when there is a
 * body, and `authorization` when that header is already in `headers`. `keyid` is the JWK `kid`.
 */
export function signRequest(key: ClientKey, request: {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  created?: number;
  nonce?: string;
  label?: string;
}): SignedHeaders {
  const url = new URL(request.url).href;
  const lower: Record<string, string> = {};
  for (const [name, value] of Object.entries(request.headers ?? {})) lower[name.toLowerCase()] = value;
  const components = ['@method', '@target-uri'];
  const added: SignedHeaders = { signature: '', 'signature-input': '' };
  if (request.body !== undefined && request.body.length > 0) {
    added['content-digest'] = contentDigest(request.body);
    lower['content-digest'] = added['content-digest'];
    components.push('content-digest');
  }
  if (lower.authorization) components.push('authorization');
  const params = signatureParams(components, {
    created: request.created ?? Math.floor(Date.now() / 1000),
    nonce: request.nonce ?? randomBytes(16).toString('base64url'),
    keyid: key.kid,
  });
  const base = signatureBase(components, { method: request.method, url, headers: lower }, params);
  const signature = signRaw(key, Buffer.from(base, 'utf8'));
  const label = request.label ?? 'sig1';
  added['signature-input'] = `${label}=${params}`;
  added.signature = `${label}=:${standardBase64(signature)}:`;
  return added;
}
