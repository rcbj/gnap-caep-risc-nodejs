// Subject information from a grant response (RFC 9635 section 3.4). An `id_token` assertion is checked
// here: signature against the issuer's JWKS, issuer, expiry, and audience. iya-sts puts the client
// instance id in the audience, and this client also accepts the registered application identifier.
// HMAC and `none` are refused with every other token this library verifies.

import { GnapError } from './errors.ts';
import { verifyCompactJws, type Jwk } from './ssf/jws.ts';

/** The person a grant was approved for. */
export interface Person {
  sub: string;
  iss?: string;
  /**
   * Directory username: the user part of an RFC 9493 `account` identifier
   * (`acct:uid@host`). iya-sts writes the directory uid there. `sub` stays the
   * protocol subject.
   */
  uid?: string;
  email?: string;
  name?: string;
  preferredUsername?: string;
  /** The provider session, from `sid` or `session_id`. */
  sid?: string;
  acr?: string;
  amr?: string[];
  claims: Record<string, unknown>;
  /** True when an `id_token` assertion verified. */
  assertionVerified: boolean;
}

export interface SubjectCheck {
  idTokenIssuer: string;
  /** Audiences that are known: the instance id, the application identifier, or both. */
  audiences: readonly string[];
  clockToleranceSec: number;
  keys: () => Promise<readonly Jwk[]>;
}

function strings(value: unknown): string[] {
  return (Array.isArray(value) ? value : value === undefined ? [] : [value]).map(String);
}

function num(value: unknown): number | undefined {
  return typeof value === 'number' ? value : undefined;
}

/** The user part of `acct:userpart@host`, percent-decoded. Anything else is not a username. */
function uidFromAccount(uri: string): string | undefined {
  const acct = /^acct:([^@]+)@(.+)$/.exec(uri);
  const user = acct?.[1];
  if (!user) return undefined;
  try {
    return decodeURIComponent(user);
  } catch {
    // A user part that is not valid percent-encoding is kept as sent.
    return user;
  }
}

/** Reads `subject` and, when it carries an `id_token`, verifies that assertion. */
export async function personFrom(subject: unknown, check: SubjectCheck): Promise<Person | undefined> {
  if (!subject || typeof subject !== 'object') return undefined;
  const doc = subject as { sub_ids?: unknown; assertions?: unknown };
  const subIds = Array.isArray(doc.sub_ids) ? doc.sub_ids as Record<string, unknown>[] : [];
  const issSub = subIds.find((id) => id.format === 'iss_sub' && typeof id.sub === 'string');
  const opaque = subIds.find((id) => id.format === 'opaque' && typeof id.id === 'string');
  const account = subIds.find((id) => id.format === 'account' && typeof id.uri === 'string');
  const assertions = Array.isArray(doc.assertions) ? doc.assertions as Record<string, unknown>[] : [];
  const idToken = assertions.find((a) => a.format === 'id_token' && typeof a.value === 'string');

  const claims: Record<string, unknown> = {};
  let sub = typeof issSub?.sub === 'string' ? issSub.sub : undefined;
  let iss = typeof issSub?.iss === 'string' ? issSub.iss : undefined;
  let verified = false;
  if (idToken && typeof idToken.value === 'string') {
    const { payload } = verifyCompactJws(idToken.value, await check.keys());
    if (payload.iss !== check.idTokenIssuer) {
      throw new GnapError('validation', `the id_token was issued by ${String(payload.iss)}, not ${check.idTokenIssuer}`);
    }
    if (typeof payload.sub !== 'string' || !payload.sub) throw new GnapError('validation', 'the id_token has no sub');
    if (typeof payload.exp !== 'number') throw new GnapError('validation', 'the id_token has no exp');
    const now = Math.floor(Date.now() / 1000);
    const skew = check.clockToleranceSec;
    if (payload.exp + skew < now) throw new GnapError('validation', 'the id_token has expired');
    const nbf = num(payload.nbf);
    if (nbf !== undefined && nbf - skew > now) throw new GnapError('validation', 'the id_token is not valid yet');
    const iat = num(payload.iat);
    if (iat !== undefined && iat - skew > now) throw new GnapError('validation', 'the id_token is issued in the future');
    const aud = strings(payload.aud);
    const known = check.audiences.filter(Boolean);
    if (known.length && !aud.some((one) => known.includes(one))) {
      throw new GnapError('validation', `the id_token is for ${aud.join(', ') || '(no audience)'}, not ${known.join(' or ')}`);
    }
    if (sub !== undefined && payload.sub !== sub) {
      throw new GnapError('validation', 'the id_token is about somebody other than the subject identifier');
    }
    sub = payload.sub;
    iss = String(payload.iss);
    Object.assign(claims, payload);
    verified = true;
  }
  if (!sub && opaque && typeof opaque.id === 'string') sub = opaque.id;
  if (!sub && account && typeof account.uri === 'string') sub = account.uri;
  if (!sub) return undefined;
  // RFC 9493 `account` (RFC 7565 `acct:userpart@host`). iya-sts writes the directory uid as the
  // user part, so it names the person where `sub` is an opaque identifier. The subject itself is
  // left as the protocol subject: Shared Signals match that, not the uid.
  const uid = account && typeof account.uri === 'string' ? uidFromAccount(account.uri) : undefined;
  const email = typeof claims.email === 'string' ? claims.email : undefined;
  const name = typeof claims.name === 'string' ? claims.name : undefined;
  const preferredUsername = typeof claims.preferred_username === 'string' ? claims.preferred_username : undefined;
  const sid = typeof claims.sid === 'string' ? claims.sid : typeof claims.session_id === 'string' ? claims.session_id : undefined;
  const acr = typeof claims.acr === 'string' ? claims.acr : undefined;
  const amr = Array.isArray(claims.amr) ? claims.amr.map(String) : undefined;
  return {
    sub, claims, assertionVerified: verified,
    ...(iss ? { iss } : {}),
    ...(uid ? { uid } : {}),
    ...(email ? { email } : {}),
    ...(name ? { name } : {}),
    ...(preferredUsername ? { preferredUsername } : {}),
    ...(sid ? { sid } : {}),
    ...(acr ? { acr } : {}),
    ...(amr ? { amr } : {}),
  };
}
