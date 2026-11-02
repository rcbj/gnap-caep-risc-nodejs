// The one client key. A registered GNAP client presents it by value on the first grant request and
// proves it on every request: mutual TLS (the connection's certificate), an HTTP message signature,
// or a detached JWS. The private key stays in this process.
//
// A JWK's `kid` is its RFC 7638 thumbprint, and that is the signature's `keyid`, so the two cannot
// disagree. A certificate's identity is the SHA-256 of its DER (x5t#S256). iya-sts reads a `cert`
// member as PEM, with or without the header.

import { createHash, createPrivateKey, createPublicKey, sign, X509Certificate, type KeyObject } from 'node:crypto';
import { GnapError } from './errors.ts';

export type KeyProof = 'mtls' | 'httpsig' | 'jwsd';

export interface PublicJwk {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  alg: string;
  kid: string;
}

/** The key this process signs and, for mutual TLS, presents. */
export interface ClientKey {
  proof: KeyProof;
  privateKey: KeyObject;
  /** Set for `httpsig` and `jwsd`. */
  jwk?: PublicJwk;
  /** The leaf, PEM. This is the `cert` member of a mutual-TLS key. */
  certificatePem?: string;
  /**
   * What mutual TLS presents: the leaf, then any intermediates that were in the same file.
   * A grant request names only the leaf. The handshake needs the intermediates or the
   * authorization server cannot build a path to its trust anchor.
   */
  tlsChainPem?: string;
  /** RFC 7638 thumbprint of the JWK, or x5t#S256 of the certificate. */
  thumbprint: string;
  /** JWS `alg` (`ES256`, `RS256`, `EdDSA`, ...). HTTP signatures do not send it. */
  alg: string;
  /** The JWK `kid`. Equal to `thumbprint` for a JWK. */
  kid: string;
}

const CURVE_ALG: Record<string, string> = { 'P-256': 'ES256', 'P-384': 'ES384', 'P-521': 'ES512' };
const HASH_OF: Record<string, string> = {
  ES256: 'sha256', ES384: 'sha384', ES512: 'sha512',
  RS256: 'sha256', RS384: 'sha384', RS512: 'sha512',
  PS256: 'sha256', PS384: 'sha384', PS512: 'sha512',
};

/** RFC 7638 thumbprint. Member order is the lexicographic order the RFC requires. */
export function jwkThumbprint(jwk: { kty: string; crv?: string; x?: string; y?: string; n?: string; e?: string }): string {
  let canonical: string;
  if (jwk.kty === 'EC') canonical = JSON.stringify({ crv: jwk.crv, kty: 'EC', x: jwk.x, y: jwk.y });
  else if (jwk.kty === 'RSA') canonical = JSON.stringify({ e: jwk.e, kty: 'RSA', n: jwk.n });
  else if (jwk.kty === 'OKP') canonical = JSON.stringify({ crv: jwk.crv, kty: 'OKP', x: jwk.x });
  else throw new GnapError('config', `a ${jwk.kty} key is not a GNAP client key this library loads`);
  return createHash('sha256').update(canonical).digest('base64url');
}

function algOf(jwk: { kty: string; crv?: string; alg?: string }): string {
  if (typeof jwk.alg === 'string' && jwk.alg && jwk.alg !== 'none') return jwk.alg;
  if (jwk.kty === 'EC') {
    const alg = jwk.crv ? CURVE_ALG[jwk.crv] : undefined;
    if (!alg) throw new GnapError('config', `the curve ${jwk.crv ?? '(none)'} has no signature algorithm`);
    return alg;
  }
  if (jwk.kty === 'RSA') return 'RS256';
  if (jwk.kty === 'OKP') return 'EdDSA';
  throw new GnapError('config', `a ${jwk.kty} key is not a GNAP client key this library loads`);
}

/**
 * The public key object RFC 9635 section 7.1 puts in `client.key`, and that iya-sts stores as
 * `gnapKey`. Mutual TLS sends the certificate as PEM. The others send a JWK whose `kid` is the thumbprint.
 */
export function publicKeyObject(key: ClientKey): Record<string, unknown> {
  if (key.proof === 'mtls') {
    if (!key.certificatePem) throw new GnapError('config', 'mutual TLS needs the client certificate');
    return { proof: 'mtls', cert: key.certificatePem.trim() };
  }
  if (!key.jwk) throw new GnapError('config', `${key.proof} needs a JWK`);
  const jwk: Record<string, string> = { kty: key.jwk.kty };
  if (key.jwk.crv) jwk.crv = key.jwk.crv;
  if (key.jwk.x) jwk.x = key.jwk.x;
  if (key.jwk.y) jwk.y = key.jwk.y;
  if (key.jwk.n) jwk.n = key.jwk.n;
  if (key.jwk.e) jwk.e = key.jwk.e;
  jwk.alg = key.alg;
  jwk.kid = key.kid;
  return { proof: key.proof, jwk };
}

/** Signs `data`. ECDSA is raw R||S (ieee-p1363). EdDSA takes no digest name. RSA-PSS uses the digest length as salt. */
export function signRaw(key: ClientKey, data: Buffer): Buffer {
  if (key.alg === 'EdDSA' || key.alg === 'Ed25519') return sign(null, data, key.privateKey);
  const hash = HASH_OF[key.alg];
  if (!hash) throw new GnapError('config', `this library does not sign with ${key.alg}`);
  if (key.alg.startsWith('ES')) return sign(hash, data, { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  if (key.alg.startsWith('PS')) return sign(hash, data, { key: key.privateKey, padding: 6, saltLength: -1 });
  return sign(hash, data, key.privateKey);
}

function publicFrom(privateKey: KeyObject): PublicJwk {
  const exported = createPublicKey(privateKey).export({ format: 'jwk' }) as {
    kty: string; crv?: string; x?: string; y?: string; n?: string; e?: string; alg?: string;
  };
  const alg = algOf(exported);
  const kid = jwkThumbprint(exported);
  return {
    kty: exported.kty, alg, kid,
    ...(exported.crv ? { crv: exported.crv } : {}),
    ...(exported.x ? { x: exported.x } : {}),
    ...(exported.y ? { y: exported.y } : {}),
    ...(exported.n ? { n: exported.n } : {}),
    ...(exported.e ? { e: exported.e } : {}),
  };
}

const PEM_BEGIN = '-----BEGIN CERTIFICATE-----';
const PEM_END = '-----END CERTIFICATE-----';

/**
 * PEM certificates in the order they appear. A chain file is leaf first. A scan with indexOf rather
 * than a lazy regular expression, which is quadratic on many BEGIN lines with no END.
 */
export function certificateBlocks(pem: string): string[] {
  const blocks: string[] = [];
  let from = 0;
  for (;;) {
    const begin = pem.indexOf(PEM_BEGIN, from);
    if (begin < 0) break;
    const end = pem.indexOf(PEM_END, begin + PEM_BEGIN.length);
    if (end < 0) break;
    blocks.push(pem.slice(begin, end + PEM_END.length));
    from = end + PEM_END.length;
  }
  return blocks;
}

/**
 * Loads the private key and, when mutual TLS is the proof or a certificate was given, checks that the
 * certificate is that key's. `proof` defaults to mutual TLS when a certificate is present.
 * A file with several certificates is a chain: the key is the first, and the handshake sends all of them.
 */
export function loadClientKey(privateKeyPem: string, certificatePem: string | undefined, proof: KeyProof | undefined): ClientKey {
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey(privateKeyPem);
  } catch (err) {
    throw new GnapError('config', `the private key could not be read: ${(err as Error).message}`, { cause: err });
  }
  const jwk = publicFrom(privateKey);
  let certificate: X509Certificate | undefined;
  if (certificatePem) {
    try {
      certificate = new X509Certificate(certificatePem);
    } catch (err) {
      throw new GnapError('config', `the certificate could not be read: ${(err as Error).message}`, { cause: err });
    }
    const fromKey = createPublicKey(privateKey).export({ type: 'spki', format: 'der' }) as Buffer;
    const fromCert = certificate.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    if (!fromKey.equals(fromCert)) throw new GnapError('config', 'the certificate is not the public half of the private key');
  }
  const chosen: KeyProof = proof ?? (certificate ? 'mtls' : 'httpsig');
  if (chosen === 'mtls' && !certificate) throw new GnapError('config', 'keyProof "mtls" needs certificate');
  if (chosen === 'mtls') {
    const blocks = certificateBlocks(certificatePem!);
    const leafPem = `${(blocks[0] ?? certificatePem!).trim()}\n`;
    const tlsChainPem = `${(blocks.length ? blocks : [certificatePem!]).map((block) => block.trim()).join('\n')}\n`;
    const thumbprint = createHash('sha256').update(certificate!.raw).digest('base64url');
    return {
      proof: 'mtls', privateKey, jwk, certificatePem: leafPem, tlsChainPem,
      thumbprint, alg: jwk.alg, kid: jwk.kid,
    };
  }
  return { proof: chosen, privateKey, jwk, ...(certificatePem ? { certificatePem } : {}), thumbprint: jwk.kid, alg: jwk.alg, kid: jwk.kid };
}
