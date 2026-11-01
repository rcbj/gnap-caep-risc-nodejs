#!/usr/bin/env node
// Writes the demo's (or any configuration's) P-256 private key and self-signed certificate.
//   gnap-caep-risc-nodejs generate-key --config demo/gnap.json [--cn name] [--days 1095] [--force]

import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createSelfSignedKeyPair } from './x509.ts';

function usage(): string {
  return `Usage: gnap-caep-risc-nodejs generate-key --config gnap.json [--cn name] [--days 1095] [--force]

Writes a P-256 private key and a self-signed certificate at the file: paths in the configuration
(privateKey and certificate). A path that already exists is left alone unless --force is given.`;
}

function destination(raw: string | undefined, base: string, what: string): string | undefined {
  if (!raw) return undefined;
  if (raw.startsWith('env:')) throw new Error(`${what} is ${raw}; this command only writes file: paths`);
  if (raw.includes('-----BEGIN')) throw new Error(`${what} is inline PEM; this command only writes file: paths`);
  const path = raw.startsWith('file:') ? raw.slice(5) : raw;
  return isAbsolute(path) ? path : resolve(base, path);
}

export function main(argv: readonly string[] = process.argv.slice(2)): void {
  if (argv[0] !== 'generate-key') {
    console.log(usage());
    if (argv.length) process.exitCode = 1;
    return;
  }
  let config = '';
  let cn = '';
  let days = 1095;
  let force = false;
  for (let i = 1; i < argv.length; i += 1) {
    const arg = argv[i]!;
    const value = () => {
      const next = argv[++i];
      if (next === undefined) throw new Error(`${arg} needs a value`);
      return next;
    };
    if (arg === '--config') config = value();
    else if (arg === '--cn') cn = value();
    else if (arg === '--days') days = Number(value());
    else if (arg === '--force') force = true;
    else if (arg === '--help' || arg === '-h') {
      console.log(usage());
      return;
    } else throw new Error(`Unknown argument ${arg}\n${usage()}`);
  }
  if (!config) throw new Error(`--config is required\n${usage()}`);
  if (!Number.isFinite(days) || days < 1) throw new Error('--days must be a positive number');
  const full = resolve(config);
  const raw = JSON.parse(readFileSync(full, 'utf8')) as { privateKey?: string; certificate?: string; application?: string; display?: { name?: string } };
  const base = dirname(full);
  const keyPath = destination(raw.privateKey, base, 'privateKey');
  const certPath = destination(raw.certificate, base, 'certificate');
  if (!keyPath) throw new Error('the configuration has no privateKey path to write');
  if (!force && existsSync(keyPath) && (!certPath || existsSync(certPath))) {
    console.log(`Key already at ${keyPath}. Pass --force to replace it.`);
    return;
  }
  const pair = createSelfSignedKeyPair({ commonName: cn || raw.display?.name || raw.application || 'gnap-client', days });
  mkdirSync(dirname(keyPath), { recursive: true });
  writeFileSync(keyPath, pair.privateKeyPem, { mode: 0o600 });
  if (certPath) {
    mkdirSync(dirname(certPath), { recursive: true });
    writeFileSync(certPath, pair.certificatePem);
  }
  console.log(`Wrote ${keyPath}`);
  if (certPath) console.log(`Wrote ${certPath}`);
  console.log(`sha256 ${pair.certificate.fingerprint256}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    main();
  } catch (err) {
    console.error((err as Error).message);
    process.exit(1);
  }
}

