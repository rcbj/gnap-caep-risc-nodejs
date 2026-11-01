// The interaction finish hash, RFC 9635 section 4.2.3:
// base64url(SHA-256(clientNonce + "\n" + serverNonce + "\n" + interact_ref + "\n" + grant endpoint)).
// The browser carries the hash. The continuation token never leaves this process.

import { createHash, timingSafeEqual } from 'node:crypto';

/** RFC 9635 section 4.2.3. `grantEndpoint` is the exact URL the grant request was posted to. */
export function interactionHash(clientNonce: string, serverNonce: string, interactRef: string, grantEndpoint: string): string {
  const input = `${clientNonce}\n${serverNonce}\n${interactRef}\n${grantEndpoint}`;
  return createHash('sha256').update(input).digest('base64url');
}

/** Constant-time comparison of two hashes. Different lengths are not equal. */
export function hashEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
