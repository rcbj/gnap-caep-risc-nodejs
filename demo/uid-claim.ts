// The display name from a GNAP access-token JWT. RFC 9635 section 3.2.1 leaves the token opaque
// to the client for authorization. This demo still reads one configured claim, `uid`, so the
// heading can show the name the application asked iya-sts to put on the token. Anything that is
// not a compact JWT, or a payload without a string `uid`, leaves the account identifier in place.

export function uidFromAccessToken(token: string): string | undefined {
  const part = token.split('.')[1];
  if (!part) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as { uid?: unknown };
    return typeof payload.uid === 'string' && payload.uid ? payload.uid : undefined;
  } catch {
    return undefined;
  }
}

export function personWithAccessTokenUid<T extends { uid?: string }>(person: T, accessToken: string): T {
  const uid = uidFromAccessToken(accessToken);
  if (!uid || uid === person.uid) return person;
  return { ...person, uid };
}
