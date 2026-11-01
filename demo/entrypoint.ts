// Sets tlsCa from the authorization server's listener chain, then starts the demo.
// The chain is not known when the image is built, and demo/generated is mounted read-only, so the
// chain and the configuration the process reads are written under /tmp.

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchTlsChain } from 'gnap-caep-risc-nodejs';

const here = dirname(fileURLToPath(import.meta.url));
const sourcePath = resolve(process.env.GNAP_CONFIG || resolve(here, 'gnap.json'));
const runtimePath = '/tmp/gnap.runtime.json';
const caPath = '/tmp/sts-listener-ca.pem';

interface RuntimeConfig {
  grantEndpoint?: string;
  tlsCa?: string;
  privateKey?: string;
  certificate?: string;
}

/**
 * The process reads a copy under /tmp, and relative paths are resolved from that copy's directory.
 * A `file:` or plain path in the source is therefore anchored to the source file before the copy
 * is written. `env:` and inline PEM stay as they are.
 */
function anchorPath(value: string | undefined, baseDir: string): string | undefined {
  if (!value || value.startsWith('env:') || value.includes('-----BEGIN')) return value;
  const prefixed = value.startsWith('file:');
  const raw = prefixed ? value.slice(5) : value;
  if (isAbsolute(raw)) return value;
  const full = resolve(baseDir, raw);
  return prefixed ? `file:${full}` : full;
}

const doc = JSON.parse(readFileSync(sourcePath, 'utf8')) as RuntimeConfig;
const sourceDir = dirname(sourcePath);
doc.privateKey = anchorPath(doc.privateKey, sourceDir);
doc.certificate = anchorPath(doc.certificate, sourceDir);
doc.tlsCa = anchorPath(doc.tlsCa, sourceDir);
const configured = doc.tlsCa ?? '';
let origin = '';
try {
  if (doc.grantEndpoint) origin = new URL(doc.grantEndpoint).origin;
} catch {
  origin = '';
}

if (configured.startsWith('env:')) {
  console.log(`tlsCa is ${configured}; leaving the parameter as it is`);
} else if (!origin) {
  console.warn('gnap.json has no grant endpoint, so tlsCa was not set from a listener');
} else {
  try {
    const chain = await fetchTlsChain(origin);
    writeFileSync(caPath, chain.pem);
    doc.tlsCa = caPath;
    console.log(`tlsCa set from ${origin} (${chain.count} certificate(s)), sha256 ${chain.leaf.fingerprint256}`);
  } catch (err) {
    console.warn(`could not read the listener chain at ${origin} (${(err as Error).message}); tlsCa stays ${configured || 'unset'}`);
  }
}

writeFileSync(runtimePath, `${JSON.stringify(doc, null, 2)}\n`);
process.env.GNAP_CONFIG = runtimePath;
await import('./server.ts');
