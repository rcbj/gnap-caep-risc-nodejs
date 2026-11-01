#!/usr/bin/env node
/**
 * Registers the demo as a GNAP client on a running iya-sts.
 *
 *   1. the listener's CA trust chain, written to the configuration's tlsCa file on every run. The
 *      bundle is GET /tls/server-certificate (leaf, intermediates, and the root). The handshake's
 *      chain is used when that document is not served. An inline PEM or `env:` value is left alone.
 *      The management calls below do not use that file: they skip verification;
 *   2. the application, in the realm the grant endpoint names: kind gnap-client, protocol gnap, the
 *      public key from the configuration (mutual TLS sends the certificate as PEM), the finish URI,
 *      redirect as the only start mode, gnapBearerTokens FALSE, and oauthAllowedScope from `access`.
 *      A re-run does not send the key again. No class_id and no browser origin;
 *   3. membership of SSF_READ and SSF_MANAGE for whichever of ssf.read and ssf.manage `access` names,
 *      and authn.multipleAccounts so one browser can hold several people;
 *   4. a test user, gnap-demo-user, in the groups ssf-read and ssf-manage.
 *
 * The key is written by `npm run generate-key`, not by this script.
 *
 *   ADMIN_API_CLIENT_SECRET=… node scripts/configure-iya-sts.ts
 *   node scripts/configure-iya-sts.ts --config demo/gnap.json --dry-run
 *
 * The management API token is minted as iya-sts's seeded client sts-api-client (client_credentials,
 * HTTP Basic), audienced to <base>/admin-api, scope admin:read admin:write. The secret is
 * ADMIN_API_CLIENT_SECRET or STS_ADMIN_API_CLIENT_SECRET.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { GnapClient, publicKeyObject } from '../packages/gnap-caep-risc-nodejs/src/index.ts';
import { send } from '../packages/gnap-caep-risc-nodejs/src/http.ts';
import { demoPort, redirectsFor } from './redirects.mjs';
import { saveTrustChain, trustPath } from './trust-chain.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export const SSF_ROLES = [
  { scope: 'ssf.read', role: 'SSF_READ', group: 'ssf-read' },
  { scope: 'ssf.manage', role: 'SSF_MANAGE', group: 'ssf-manage' },
] as const;

/** The realm setting that lets one browser hold several signed-in people. */
export const MULTIPLE_ACCOUNTS = { key: 'authn.multipleAccounts', value: true } as const;

/** Management calls do not verify the development certificate. The demo trusts the saved chain. */
export function adminTls(): { rejectUnauthorized: false } {
  return { rejectUnauthorized: false };
}

export function usage(): string {
  return `Usage: node scripts/configure-iya-sts.ts [--config path] [--idp url] [--public-url url]
                                        [--test-user name | --no-test-user] [--dry-run]

  --config        The demo's GNAP configuration (default: demo/gnap.json)
  --idp           iya-sts's base URL; the realm's, e.g. https://host/realm/acme, for a trust realm
                  (default: the grant endpoint's origin, with a trailing /gnap removed, or $IYA_STS_URL)
  --public-url    Replace the origin of the file's finish URI and display URI with this URL, and
                  keep their paths (default: unset; $PUBLIC_URL). Without it, a loopback finish
                  URI follows the running demo's PORT, then $PORT. A non-loopback finish URI is
                  left as written.
  --test-user     The test user to create (default: gnap-demo-user). Its password is
                  $GNAP_DEMO_USER_PASSWORD, or one is generated and printed once. With that variable
                  set, an existing user's password is replaced.
  --no-test-user  Do not create a test user.
  --dry-run       Print what would be done, and send nothing.

The management API secret is ADMIN_API_CLIENT_SECRET or STS_ADMIN_API_CLIENT_SECRET.
Run npm run generate-key before a real run, so the public key exists.`;
}

export interface Args {
  config: string;
  idp: string;
  publicUrl: string;
  /** Set when --public-url or PUBLIC_URL was given. The default does not count. */
  publicUrlGiven: boolean;
  testUser: string;
  dryRun: boolean;
  help: boolean;
  /** Set when --idp was given, so the file's grant endpoint does not replace it. */
  idpGiven: boolean;
}

export function parseArgs(argv: readonly string[], env: NodeJS.ProcessEnv = process.env): Args {
  const out: Args = {
    config: resolve(repoRoot, 'demo/gnap.json'),
    idp: (env.IYA_STS_URL || '').replace(/\/+$/, ''),
    publicUrl: (env.PUBLIC_URL || 'http://localhost:3000').replace(/\/+$/, ''),
    publicUrlGiven: Boolean(env.PUBLIC_URL),
    testUser: 'gnap-demo-user',
    dryRun: false,
    help: false,
    idpGiven: Boolean(env.IYA_STS_URL),
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    const value = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${arg} needs a value\n${usage()}`);
      return v;
    };
    if (arg === '--help' || arg === '-h') out.help = true;
    else if (arg === '--config') out.config = resolve(value());
    else if (arg === '--idp') {
      out.idp = value().replace(/\/+$/, '');
      out.idpGiven = true;
    } else if (arg === '--public-url') {
      out.publicUrl = value().replace(/\/+$/, '');
      out.publicUrlGiven = true;
    } else if (arg === '--test-user') out.testUser = value().trim();
    else if (arg === '--no-test-user') out.testUser = '';
    else if (arg === '--dry-run') out.dryRun = true;
    else throw new Error(`Unknown argument ${arg}\n${usage()}`);
  }
  if (out.idp) {
    const u = new URL(out.idp);
    if (u.protocol !== 'https:') throw new Error(`--idp must be https, not ${out.idp}`);
  }
  if (!out.publicUrl) throw new Error('--public-url is empty');
  return out;
}

export interface DemoFiles {
  application: string;
  name: string;
  finishUri: string;
  displayUri?: string;
  scopes: string[];
  interactionStart: string[];
  keyProof: string;
  grantEndpoint: string;
  tlsCa?: string;
  transmitter?: string;
}

/** The client the configuration names. Registration then applies {@link redirectsFor}. */
export function filesOf(configPath: string, publicUrl: string): DemoFiles {
  const raw = JSON.parse(readFileSync(configPath, 'utf8')) as {
    application?: string;
    display?: { name?: string; uri?: string };
    access?: unknown[];
    keyProof?: string;
    certificate?: string;
    grantEndpoint?: string;
    finishUri?: string;
    interactionStart?: string[];
    tlsCa?: string;
    transmitterIssuer?: string;
    ssf?: { transmitter?: string };
  };
  const base = dirname(configPath);
  const application = String(raw.application ?? '').trim();
  const grantEndpoint = String(raw.grantEndpoint ?? '').trim();
  if (!application) throw new Error(`${configPath} has no application`);
  if (!grantEndpoint) throw new Error(`${configPath} has no grantEndpoint`);
  const origin = publicUrl.endsWith('/') ? publicUrl : `${publicUrl}/`;
  const finishUri = String(raw.finishUri ?? '').trim() || new URL('callback', origin).href;
  const access = Array.isArray(raw.access) ? raw.access : ['ssf.read', 'ssf.manage'];
  const scopes = access.filter((item): item is string => typeof item === 'string' && item.trim().length > 0);
  const keyProof = String(raw.keyProof ?? (raw.certificate ? 'mtls' : 'httpsig'));
  const transmitter = (raw.ssf?.transmitter ?? raw.transmitterIssuer)?.replace(/\/+$/, '');
  const tlsCa = trustPath(raw.tlsCa, base);
  return {
    application,
    name: raw.display?.name?.trim() || `${application} demo`,
    finishUri,
    ...(raw.display?.uri ? { displayUri: raw.display.uri } : {}),
    scopes,
    interactionStart: raw.interactionStart?.length ? raw.interactionStart : ['redirect'],
    keyProof,
    grantEndpoint,
    ...(tlsCa ? { tlsCa } : {}),
    ...(transmitter ? { transmitter } : {}),
  };
}

/** The provider base implied by a grant endpoint: a trailing `/gnap` is the protocol, not the realm. */
export function idpFromGrant(grantEndpoint: string): string {
  const u = new URL(grantEndpoint);
  u.pathname = u.pathname.replace(/\/gnap\/?$/, '');
  u.search = '';
  u.hash = '';
  return u.href.replace(/\/$/, '');
}

/** The realm's base and the origin a token is minted at. */
export function realmOf(idp: string): { origin: string; base: string } {
  const u = new URL(idp);
  if (u.protocol !== 'https:') throw new Error(`the provider must be https, not ${idp}`);
  const path = u.pathname.replace(/\/+$/, '');
  if (path && !/^\/realm\/[^/]+$/.test(path)) throw new Error(`--idp must be iya-sts's base URL or a realm's (/realm/<id>), not ${idp}`);
  return { origin: u.origin, base: `${u.origin}${path}` };
}

export interface Call {
  method: string;
  path: string;
  body?: unknown;
  why: string;
  /** create: only when the application is new. exists: only when it already is. always: either way. */
  when: 'create' | 'exists' | 'always';
}

/**
 * The fields registered on create. `gnapKey` is the public key object as one JSON string. It is not
 * repeated when the application already exists, so a re-run does not replace the key.
 */
export function applicationFields(files: DemoFiles, keyJson: string, includeKey: boolean): Record<string, unknown> {
  return {
    ...(includeKey ? { gnapKey: keyJson } : {}),
    gnapFinishUri: [files.finishUri],
    gnapInteractionStartModes: files.interactionStart,
    gnapBearerTokens: 'FALSE',
    ...(files.displayUri ? { gnapDisplayUri: files.displayUri } : {}),
    oauthAllowedScope: files.scopes,
  };
}

/** What a product-mode realm's attribute policy requires of every person. */
export function userAttributes(username: string): Record<string, string> {
  return {
    cn: `GNAP Demo ${username}`,
    givenName: 'GNAP',
    sn: 'Demo',
    displayName: `GNAP Demo ${username}`,
    mail: `${username}@gnap-demo.test`,
  };
}

/**
 * The management API calls. The create call carries the public key. The calls marked `exists` add the
 * same values except the key.
 */
export function planFor(files: DemoFiles, base: string, testUser: string, keyJson: string): Call[] {
  const calls: Call[] = [
    {
      method: 'POST', path: `${base}/admin-api/applications/create`, when: 'create',
      why: `register ${files.application}`,
      body: {
        identifier: files.application,
        name: files.name,
        kind: 'gnap-client',
        protocols: ['gnap'],
        fields: applicationFields(files, keyJson, true),
      },
    },
  ];
  calls.push({
    method: 'POST', path: `${base}/admin-api/applications/add`, when: 'exists',
    why: 'declare protocol gnap',
    body: { application: files.application, attribute: 'appAllowedProtocol', value: 'gnap' },
  });
  const again = applicationFields(files, keyJson, false);
  for (const [attribute, raw] of Object.entries(again)) {
    const values = Array.isArray(raw) ? raw.map(String) : [String(raw)];
    for (const value of values) {
      calls.push({
        method: 'POST', path: `${base}/admin-api/applications/add`, when: 'exists',
        why: `add ${attribute}`,
        body: { application: files.application, attribute, value },
      });
    }
  }
  calls.push({
    method: 'POST', path: `${base}/admin-api/config/set`, when: 'always',
    why: 'let one browser hold several accounts',
    body: MULTIPLE_ACCOUNTS,
  });
  for (const { scope, role } of SSF_ROLES) {
    if (!files.scopes.includes(scope)) continue;
    calls.push({
      method: 'POST', path: `${base}/admin-api/roles/add-member`, when: 'always',
      why: `hold ${role}, which authorizes ${scope}`,
      body: { role, kind: 'application', member: files.application },
    });
  }
  if (testUser) {
    calls.push({
      method: 'POST', path: `${base}/admin-api/users/create`, when: 'always',
      why: `create the test user ${testUser}`,
      body: { username: testUser, invent: false, credential: 'generate', attributes: userAttributes(testUser) },
    });
    for (const { scope, group } of SSF_ROLES) {
      if (!files.scopes.includes(scope)) continue;
      calls.push({
        method: 'POST', path: `${base}/admin-api/groups/add-member`, when: 'always',
        why: `put ${testUser} in ${group}`,
        body: { group, member: testUser },
      });
    }
  }
  return calls;
}

async function json(url: string, init: { method?: string; headers?: Record<string, string>; body?: string }) {
  const answer = await send(url, init, adminTls(), 'config');
  let body: Record<string, unknown> = {};
  try {
    body = answer.body ? JSON.parse(answer.body) as Record<string, unknown> : {};
  } catch {
    throw new Error(`${init.method ?? 'GET'} ${url} answered ${answer.status} with non-JSON: ${answer.body.slice(0, 300)}`);
  }
  if (answer.status === 401 || answer.status === 403) throw new Error(`${init.method ?? 'GET'} ${url} answered ${answer.status}: ${JSON.stringify(body).slice(0, 300)}`);
  return { status: answer.status, body };
}

const errorsOf = (body: Record<string, unknown>) => ([] as unknown[]).concat(body.errors ?? []).map(String);

async function mintAdminToken(base: string, secret: string): Promise<string> {
  const form = new URLSearchParams({ grant_type: 'client_credentials', scope: 'admin:read admin:write', resource: `${base}/admin-api` });
  const reply = await json(`${base}/oauth2/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`sts-api-client:${secret}`).toString('base64')}`,
    },
    body: form.toString(),
  });
  if (reply.status !== 200 || typeof reply.body.access_token !== 'string') {
    throw new Error(`the token endpoint answered ${reply.status} ${JSON.stringify(reply.body).slice(0, 300)}`);
  }
  return reply.body.access_token;
}

function keyJsonOf(configPath: string): string {
  return JSON.stringify(publicKeyObject(GnapClient.fromFile(configPath).key));
}

/** PORT from the running gnap-demo container, when compose has one. Docker being absent is not an error. */
export function containerPort(cwd = repoRoot): string | undefined {
  try {
    const id = execFileSync('docker', ['compose', 'ps', '-q', 'gnap-demo'], {
      cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    }).trim().split('\n')[0];
    if (!id) return undefined;
    const env = execFileSync('docker', ['inspect', '-f', '{{range .Config.Env}}{{println .}}{{end}}', id], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    });
    return env.split('\n').find((line) => line.startsWith('PORT='))?.slice('PORT='.length);
  } catch {
    return undefined;
  }
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<void> {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(usage());
    return;
  }
  const files = filesOf(args.config, args.publicUrl);
  const port = demoPort(process.env.PORT, containerPort());
  const uris = redirectsFor(files.finishUri, files.displayUri, {
    publicUrl: args.publicUrl, publicUrlGiven: args.publicUrlGiven, port,
  });
  files.finishUri = uris.finishUri;
  if (uris.displayUri) files.displayUri = uris.displayUri;
  const idp = args.idp || idpFromGrant(files.grantEndpoint);
  const { origin, base } = realmOf(idp);

  let keyJson = '';
  try {
    keyJson = keyJsonOf(args.config);
  } catch (err) {
    if (!args.dryRun) {
      throw new Error(`the client key could not be read (${(err as Error).message}). Run npm run generate-key -- --config ${args.config} first.`);
    }
    keyJson = '<the public key>';
  }

  if (args.dryRun) {
    if (files.tlsCa) console.log(`# would save ${origin}'s listener CA trust chain to ${files.tlsCa}`);
    console.log(`# key proof ${files.keyProof}; management calls set rejectUnauthorized false`);
    for (const call of planFor(files, base, args.testUser, keyJson)) {
      console.log(`${call.method} ${call.path}  # ${call.when}: ${call.why}\n${JSON.stringify(call.body ?? {}, null, 2)}`);
    }
    return;
  }

  if (files.tlsCa) {
    const chain = await saveTrustChain(origin, files.tlsCa);
    console.log(`Saved ${origin}'s listener CA trust chain (${chain.count} certificate(s)) to ${files.tlsCa}`);
    console.log(`  trust anchor ${chain.anchor.subject.replace(/\n/g, ', ')}`);
    console.log(`  sha256 ${chain.anchor.fingerprint256}`);
    console.log('  Compare the anchor with the Root CA on iya-sts\'s Server configuration, PKI page.');
  }

  const adminSecret = process.env.ADMIN_API_CLIENT_SECRET || process.env.STS_ADMIN_API_CLIENT_SECRET || '';
  if (!adminSecret) throw new Error('neither ADMIN_API_CLIENT_SECRET nor STS_ADMIN_API_CLIENT_SECRET is set, so no /admin-api token can be minted.');
  const token = await mintAdminToken(base, adminSecret);
  const api = (path: string, body: unknown, method = 'POST') => json(`${base}/admin-api${path}`, {
    method,
    headers: {
      accept: 'application/json',
      authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });

  const plan = planFor(files, base, args.testUser, keyJson);
  const create = plan.find((call) => call.when === 'create');
  const created = await api('/applications/create', create?.body);
  let fresh = false;
  if (created.body.ok) {
    fresh = true;
    console.log(`Registered ${files.application}. The key is the one in the configuration; it was not written here.`);
  } else if (errorsOf(created.body).some((e) => /already in this registry/i.test(e))) {
    console.log(`${files.application} is already registered; adding the demo's values. The registered key is unchanged.`);
    for (const call of plan.filter((one) => one.when === 'exists')) {
      const added = await api(call.path.slice(`${base}/admin-api`.length), call.body);
      const errors = errorsOf(added.body).join(' ');
      if (!added.body.ok && !/already/i.test(errors)) throw new Error(`${call.why}: refused: ${JSON.stringify(added.body).slice(0, 400)}`);
    }
  } else {
    throw new Error(`iya-sts refused to create ${files.application}: ${JSON.stringify(created.body).slice(0, 500)}`);
  }

  for (const call of plan.filter((one) => one.when === 'always' && (one.path.endsWith('/config/set') || one.path.endsWith('/roles/add-member')))) {
    const answered = await api(call.path.slice(`${base}/admin-api`.length), call.body);
    const errors = errorsOf(answered.body).join(' ');
    if (!answered.body.ok && !/already/i.test(errors)) throw new Error(`${call.why}: refused: ${JSON.stringify(answered.body).slice(0, 400)}`);
    if (!answered.body.ok) console.log(`  ${call.why}: already so`);
  }
  if (fresh) console.log('authn.multipleAccounts is on, and the Shared Signals roles were granted for the access rights in the file.');

  if (args.testUser) {
    const found = await api(`/users?user=${encodeURIComponent(args.testUser)}`, undefined, 'GET');
    const password = process.env.GNAP_DEMO_USER_PASSWORD || '';
    if (found.body.known === true && password) {
      const set = await api('/users/set-password', { user: args.testUser, password, passwordConfirm: password });
      if (!set.body.ok) throw new Error(`setting ${args.testUser}'s password was refused: ${JSON.stringify(set.body).slice(0, 300)}`);
      console.log(`User ${args.testUser} already exists; its password is now GNAP_DEMO_USER_PASSWORD.`);
    } else if (found.body.known === true) {
      console.log(`User ${args.testUser} already exists; its password is unchanged (set GNAP_DEMO_USER_PASSWORD to replace it).`);
    } else {
      const body = password
        ? { username: args.testUser, invent: false, credential: 'password', password, passwordConfirm: password, attributes: userAttributes(args.testUser) }
        : { username: args.testUser, invent: false, credential: 'generate', attributes: userAttributes(args.testUser) };
      const made = await api('/users/create', body);
      if (!made.body.ok) throw new Error(`creating ${args.testUser} was refused: ${JSON.stringify(made.body).slice(0, 300)}`);
      console.log(`Created user ${args.testUser}.`);
      if (made.body.password) console.log(`Generated password for ${args.testUser} (shown once): ${String(made.body.password)}`);
    }
    for (const call of plan.filter((one) => one.path.endsWith('/groups/add-member'))) {
      const added = await api('/groups/add-member', call.body);
      if (!added.body.ok) throw new Error(`adding ${args.testUser} to a group was refused: ${JSON.stringify(added.body).slice(0, 300)}`);
      const group = (call.body as { group?: string }).group;
      console.log(`${args.testUser} ${added.body.changed === false ? 'was already' : 'is now'} in ${group}.`);
    }
  }
  console.log(`application: ${files.application}`);
  console.log(`grant:       ${files.grantEndpoint}`);
  console.log(`finish:      ${files.finishUri}`);
  console.log(`proof:       ${files.keyProof}`);
  console.log('Done. Start the demo with: docker compose up --build');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((err: Error) => {
    console.error(err.message);
    process.exit(1);
  });
}
