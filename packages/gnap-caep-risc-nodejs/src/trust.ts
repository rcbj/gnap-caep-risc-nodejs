// The authorization server's listener chain, taken from the handshake. This is how a setup script and
// the demo container learn which certificates to trust before any of them is in node's store.

import { X509Certificate } from 'node:crypto';
import { connect, type DetailedPeerCertificate } from 'node:tls';

export interface TlsChain {
  pem: string;
  leaf: X509Certificate;
  count: number;
}

/** Every certificate the listener presents, leaf first. Verification is off: this is the first trust. */
export function fetchTlsChain(origin: string): Promise<TlsChain> {
  const u = new URL(origin);
  return new Promise((resolvePromise, reject) => {
    const socket = connect({
      host: u.hostname,
      port: Number(u.port || 443),
      servername: u.hostname,
      rejectUnauthorized: false,
    }, () => {
      const certs: X509Certificate[] = [];
      const seen = new Set<string>();
      let current: DetailedPeerCertificate | undefined = socket.getPeerCertificate(true);
      while (current?.raw && current.fingerprint256 && !seen.has(current.fingerprint256)) {
        seen.add(current.fingerprint256);
        certs.push(new X509Certificate(current.raw));
        const next: DetailedPeerCertificate | undefined = current.issuerCertificate;
        if (!next || next === current || !next.raw) break;
        current = next;
      }
      socket.end();
      const leaf = certs[0];
      if (!leaf) {
        reject(new Error(`no certificate from ${origin}`));
        return;
      }
      resolvePromise({
        pem: `${certs.map((cert) => cert.toString().trim()).join('\n')}\n`,
        leaf,
        count: certs.length,
      });
    });
    socket.setTimeout(10_000, () => {
      socket.destroy();
      reject(new Error(`${origin} did not complete a TLS handshake`));
    });
    socket.on('error', reject);
  });
}
