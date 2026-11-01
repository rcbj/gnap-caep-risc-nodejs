// A self-signed P-256 certificate for the client's mutual TLS key, made with node:crypto alone.
// Node can make keys but not certificates. The DER is small and written by hand. ECDSA-with-SHA256
// (1.2.840.10045.4.3.2) has no AlgorithmIdentifier parameters. The signature is DER, which is what
// X.509 wants; HTTP signatures and detached JWS use raw R||S instead, and that is not this file.

import { generateKeyPairSync, randomBytes, sign, X509Certificate, type KeyObject } from 'node:crypto';

function length(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v >>= 8) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

const tlv = (tag: number, ...content: Buffer[]) => {
  const body = Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), length(body.length), body]);
};
const seq = (...c: Buffer[]) => tlv(0x30, ...c);
const setOf = (...c: Buffer[]) => tlv(0x31, ...c);

function oid(dotted: string): Buffer {
  const parts = dotted.split('.').map(Number);
  const first = parts[0] ?? 0;
  const second = parts[1] ?? 0;
  const out = [first * 40 + second];
  for (const n of parts.slice(2)) {
    const chunk: number[] = [n & 0x7f];
    for (let v = n >> 7; v > 0; v >>= 7) chunk.unshift((v & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return tlv(0x06, Buffer.from(out));
}

function time(d: Date): Buffer {
  const iso = d.toISOString().replace(/[-:T]/g, '').slice(0, 14) + 'Z';
  return d.getUTCFullYear() < 2050 ? tlv(0x17, Buffer.from(iso.slice(2), 'ascii')) : tlv(0x18, Buffer.from(iso, 'ascii'));
}

const name = (cn: string) => seq(setOf(seq(oid('2.5.4.3'), tlv(0x0c, Buffer.from(cn, 'utf8')))));
// ecdsa-with-SHA256. Parameters are absent, not NULL.
const ECDSA_SHA256 = seq(oid('1.2.840.10045.4.3.2'));

function pem(label: string, der: Buffer): string {
  const body = der.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

export interface KeyPairOptions {
  /** The certificate's subject (and issuer) common name. */
  commonName: string;
  /** How long the certificate is valid for, in days. Default 1095 (three years). */
  days?: number;
  /** DNS names in subjectAltName. A TLS listener needs these; a client certificate does not. */
  dns?: string[];
  /** IPv4 addresses in subjectAltName. */
  ip?: string[];
}

export interface KeyPair {
  /** The private key, PKCS#8 PEM. */
  privateKeyPem: string;
  /** The self-signed certificate, PEM. */
  certificatePem: string;
  certificate: X509Certificate;
  privateKey: KeyObject;
}

/** A new P-256 key and a self-signed certificate whose only key usage is digitalSignature. */
export function createSelfSignedKeyPair(options: KeyPairOptions): KeyPair {
  const days = options.days ?? 1095;
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const serial = randomBytes(16);
  serial[0] = (serial[0] ?? 0) & 0x7f;
  const notBefore = new Date(Date.now() - 60_000);
  const notAfter = new Date(notBefore.getTime() + days * 86_400_000);
  const alt: Buffer[] = [
    ...(options.dns ?? []).map((dns) => tlv(0x82, Buffer.from(dns, 'ascii'))),
    ...(options.ip ?? []).map((ip) => tlv(0x87, Buffer.from(ip.split('.').map((part) => Number(part))))),
  ];
  const extensions = tlv(0xa3, seq(
    seq(oid('2.5.29.19'), tlv(0x01, Buffer.from([0xff])), tlv(0x04, seq())),
    // keyUsage, critical: digitalSignature only. BIT STRING unused bits 7, value 0x80.
    seq(oid('2.5.29.15'), tlv(0x01, Buffer.from([0xff])), tlv(0x04, tlv(0x03, Buffer.from([0x07, 0x80])))),
    ...(alt.length ? [seq(oid('2.5.29.17'), tlv(0x04, seq(...alt)))] : []),
  ));
  const spki = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const tbs = seq(
    tlv(0xa0, tlv(0x02, Buffer.from([0x02]))),
    tlv(0x02, serial),
    ECDSA_SHA256,
    name(options.commonName),
    seq(time(notBefore), time(notAfter)),
    name(options.commonName),
    spki,
    extensions,
  );
  const signature = sign('sha256', tbs, privateKey);
  const der = seq(tbs, ECDSA_SHA256, tlv(0x03, Buffer.concat([Buffer.from([0x00]), signature])));
  const certificatePem = pem('CERTIFICATE', der);
  const certificate = new X509Certificate(certificatePem);
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  return { privateKeyPem, certificatePem, certificate, privateKey };
}
