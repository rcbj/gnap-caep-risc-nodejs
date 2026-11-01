// Detached JWS key proof, RFC 9635 section 7.3.3. The header carries htm, the exact target URI,
// created, and ath (base64url(SHA-256 of the access token)) when a token is presented. The payload
// is base64url(SHA-256 of the raw body), or empty when there is no body. The signature is over
// headerB64 + "." + that payload, not over a second encoding of it. ECDSA is raw R||S.

import { createHash } from 'node:crypto';
import type { ClientKey } from './keys.ts';
import { signRaw } from './keys.ts';

/** `ath`: base64url(SHA-256 of the token value itself, not of the Authorization header). */
export function athOf(token: string): string {
  return createHash('sha256').update(Buffer.from(token, 'ascii')).digest('base64url');
}

/**
 * A compact detached JWS for the `Detached-JWS` header. `url` is the exact target URI. `token` is the
 * GNAP access token value, when one is presented.
 */
export function detachedJws(key: ClientKey, request: {
  method: string;
  url: string;
  body?: string;
  token?: string;
  created?: number;
}): string {
  const header: Record<string, unknown> = {
    typ: 'gnap-binding-jwsd',
    alg: key.alg,
    kid: key.kid,
    htm: request.method.toUpperCase(),
    uri: new URL(request.url).href,
    created: request.created ?? Math.floor(Date.now() / 1000),
  };
  if (request.token) header.ath = athOf(request.token);
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payload = request.body !== undefined && request.body.length > 0
    ? createHash('sha256').update(Buffer.from(request.body, 'utf8')).digest('base64url')
    : '';
  const signature = signRaw(key, Buffer.from(`${encodedHeader}.${payload}`, 'ascii'));
  return `${encodedHeader}.${payload}.${signature.toString('base64url')}`;
}
