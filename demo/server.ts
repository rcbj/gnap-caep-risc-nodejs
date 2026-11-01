// The demo: a traditional server-rendered web application that signs people in with GNAP through
// gnap-caep-risc-nodejs. node:http and nothing else; Node runs this TypeScript file as it is.
//
// SEVERAL PEOPLE IN ONE BROWSER. The browser holds one cookie, `aset`, naming an ACCOUNT SET: the people
// signed in to it, each a session of their own (their own grant, events and live channel). Which one a
// tab shows is in its URL, `/u/<account>/`, an id stable for as long as that person stays signed in.
//
//   GET  /                to the first account's page, or the sign-in page when nobody is signed in
//   GET  /login           starts a grant and redirects the browser; ?add=1 adds another person;
//                         ?account=<a> asks for that person again (a user hint and expectedSub)
//   GET  /callback        the redirect finish: checks the hash, continues the grant, 303 to the account
//   POST /gnap/push       a push finish, for a deployment that registers one. This demo uses redirect.
//   GET  /u/<a>/          that account's page; ?tab=events shows its CAEP and RISC events and the stream
//   GET  /u/<a>/events    Server-Sent Events for that account
//   GET  /u/<a>/api/signals  the same events as JSON (?after=<id>)
//   POST /u/<a>/signals/verify  asks the transmitter for a verification event
//   POST /u/<a>/signals/clear   empties that account's event log
//   POST /u/<a>/logout    signs that account out of this application; the others stay
//   POST /logout          signs every account in this browser out of this application
//   GET  /healthz         for the container's health check
//
// SHARED SIGNALS starts after the first successful grant, not when the process starts, so the home page
// does not contact the authorization server. One poll stream, authenticated by a GNAP access token and
// the same key proof (mutual TLS in this demo). The latest grant is kept for that poll after the
// browser session that obtained it has signed out. An ending event ends the matching local sessions.
//
// Two cookies. `gpending` names the outstanding grants (their ids only; the continuation stays in this
// process), HMAC-signed, scoped to /callback, SameSite=Lax. It is not Secure on an http finish URI,
// including localhost. `aset` is the account set. Tokens never reach the browser.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  EVENT, GnapClient, GnapError, SignalsReceiver, trackedFromPerson,
  type Grant, type Person, type SignalEvent,
} from 'gnap-caep-risc-nodejs';
import { onPort } from '../scripts/redirects.mjs';
import { personWithAccessTokenUid } from './uid-claim.ts';

const here = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const CONFIG = resolve(process.env.GNAP_CONFIG || resolve(here, 'gnap.json'));
const SECRET = process.env.SESSION_SECRET ? Buffer.from(process.env.SESSION_SECRET) : randomBytes(32);
const SESSION_MS = 8 * 3600_000;
const MAX_SESSIONS = 10_000;
const STYLES = readFileSync(resolve(here, 'public/styles.css'));
const APP_JS = readFileSync(resolve(here, 'public/app.js'));
const SSF = (() => {
  try {
    const raw = JSON.parse(readFileSync(CONFIG, 'utf8')) as { ssf?: { transmitter?: string; pollIntervalMs?: number } };
    return raw.ssf?.transmitter ? raw.ssf : undefined;
  } catch {
    return undefined;
  }
})();

// Loaded on first use. The key is read and nothing is discovered, so the home page can render
// before the authorization server is reachable. A loopback finish URI follows the port this process
// listens on, which is the URI configure-iya-sts registers. Any other host is left as written.
let gnapClient: GnapClient | undefined;
let gnapError: string | undefined;

function readConfig(): { finishUri?: unknown; display?: { uri?: unknown } } {
  const raw = JSON.parse(readFileSync(CONFIG, 'utf8')) as { finishUri?: unknown; display?: { uri?: unknown } };
  if (typeof raw.finishUri === 'string' && raw.finishUri) raw.finishUri = onPort(raw.finishUri, PORT);
  if (raw.display && typeof raw.display.uri === 'string' && raw.display.uri) raw.display.uri = onPort(raw.display.uri, PORT);
  return raw;
}

function client(): GnapClient {
  if (!gnapClient) {
    try {
      gnapClient = GnapClient.create(GnapClient.resolve(readConfig(), dirname(CONFIG)));
      gnapError = undefined;
    } catch (err) {
      gnapError = err instanceof GnapError ? `${err.code}: ${err.message}` : (err as Error).message;
      throw err;
    }
  }
  return gnapClient;
}

function tryClient(): GnapClient | undefined {
  try {
    return client();
  } catch {
    return undefined;
  }
}

/** One received event, as the events tab draws it and the browser receives it. */
interface LoggedEvent {
  id: number;
  at: string;
  type: string;
  family: 'CAEP' | 'RISC' | 'SSF';
  ended: boolean;
  about: 'session' | 'stream';
  subject: string;
  members: Record<string, unknown>;
  jti: string;
}

interface Session {
  person: Person;
  grant: Grant;
  expires: number;
  setId: string;
  account: string;
  signals: LoggedEvent[];
}
const sessions = new Map<string, Session>();
const accountSets = new Map<string, string[]>();

function endSession(sid: string): void {
  const s = sessions.get(sid);
  sessions.delete(sid);
  if (!s) return;
  const set = accountSets.get(s.setId);
  if (set) {
    const left = set.filter((x) => x !== sid);
    if (left.length) accountSets.set(s.setId, left);
    else accountSets.delete(s.setId);
  }
}
const listeners = new Map<string, Set<ServerResponse>>();

function tell(sid: string, event: string, data: unknown, id?: number): void {
  for (const res of listeners.get(sid) ?? []) {
    res.write(`${id !== undefined ? `id: ${id}\n` : ''}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    if (event === 'signed-out') res.end();
  }
  if (event === 'signed-out') listeners.delete(sid);
}

const shortType = (uri: string) => uri.replace(/^.*\/event-type\//, '');
const familyOf = (uri: string): LoggedEvent['family'] => (/\/caep\//.test(uri) ? 'CAEP' : /\/risc\//.test(uri) ? 'RISC' : 'SSF');
// The heading and the account list prefer the access token's `uid` claim. Without that
// claim they use the user part of the account subject identifier. Shared Signals match
// the protocol subject, not either of those names.
const who = (person: Person) => person.uid || person.preferredUsername || person.email || person.name || person.sub;

const LOG_SIZE = 25;
let sequence = 0;
const verificationsAsked = new Map<string, string>();
let streamStatus: { status: string; reason?: unknown; at: string } | undefined;

function logFor(sid: string, entry: LoggedEvent): void {
  const s = sessions.get(sid);
  if (!s) return;
  s.signals.unshift(entry);
  s.signals.length = Math.min(s.signals.length, LOG_SIZE);
  tell(sid, 'signal', entry, entry.id);
}

let receiver: SignalsReceiver | undefined;
let ssfGrant: Grant | undefined;
let receiverState = SSF ? 'waiting for the first sign-in' : 'not configured (no ssf block in the configuration file)';

function proofPhrase(gnap: GnapClient | undefined): string {
  const proof = gnap?.security.keyProof;
  const how = proof === 'mtls' ? 'mutual TLS'
    : proof === 'httpsig' ? 'HTTP message signatures'
      : proof === 'jwsd' ? 'detached JWS'
        : 'its key';
  return `GNAP access token, key-bound, proved by ${how}`;
}

async function watch(sid: string, person: Person, expires: number): Promise<void> {
  if (receiver) await receiver.track(trackedFromPerson(sid, person, new Date(expires)));
}

function startReceiver(): void {
  if (!SSF || receiver) return;
  const gnap = tryClient();
  if (!gnap) return;
  const r = new SignalsReceiver({
    transmitter: SSF.transmitter!,
    tls: gnap.tls(),
    headers: async (request) => {
      if (!ssfGrant) throw new Error('no grant yet');
      ssfGrant = await gnap.ensureFresh(ssfGrant);
      return gnap.authorizationHeaders(ssfGrant, request);
    },
    description: `gnap-caep-risc-nodejs demo (${gnap.config.application})`,
    ...(SSF.pollIntervalMs ? { pollIntervalMs: SSF.pollIntervalMs } : {}),
    onEndSessions: (ids: string[], event: SignalEvent) => {
      for (const sid of ids) {
        endSession(sid);
        tell(sid, 'signed-out', { type: shortType(event.type), reason: event.payload.reason_user ?? event.payload.reason_admin ?? event.payload.reason ?? null });
      }
      console.log(`ssf: ${shortType(event.type)} ended ${ids.length} local session(s)`);
    },
  });
  r.on('*', (event: SignalEvent) => {
    const entry: LoggedEvent = {
      id: ++sequence,
      at: new Date().toISOString(),
      type: event.type,
      family: familyOf(event.type),
      ended: event.ended,
      about: 'session',
      subject: [event.subject.person, event.subject.email, event.subject.idpSession && `IdP session ${event.subject.idpSession}`]
        .filter(Boolean).join(', '),
      members: event.payload,
      jti: event.jti,
    };
    if (event.type === EVENT.verification) {
      const asker = verificationsAsked.get(String(event.payload.state ?? ''));
      verificationsAsked.delete(String(event.payload.state ?? ''));
      if (asker) logFor(asker, { ...entry, about: 'stream' });
      console.log(`ssf: verification received${asker ? '' : ' (asked by no session here)'}`);
      return;
    }
    if (event.type === EVENT.streamUpdated) {
      streamStatus = { status: String(event.payload.status ?? ''), reason: event.payload.reason, at: entry.at };
      for (const sid of listeners.keys()) tell(sid, 'stream', streamStatus);
      return;
    }
    if (!event.ended) for (const sid of event.sessions) logFor(sid, entry);
  });
  receiver = r;
  receiverState = 'starting';
  r.start().then(async () => {
    receiverState = `polling stream ${r.stream?.stream_id} at ${SSF.transmitter}`;
    for (const [sid, session] of sessions) await r.track(trackedFromPerson(sid, session.person, new Date(session.expires)));
  }, (err: Error) => {
    receiverState = `not running: ${err.message}`;
    receiver = undefined;
    console.warn(`ssf: the receiver did not start: ${err.message}`);
  });
}

function rememberGrant(grant: Grant): void {
  ssfGrant = grant;
  startReceiver();
}

const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const mac = (value: string) => createHmac('sha256', SECRET).update(value).digest('base64url');

function sealed(value: unknown): string {
  const body = Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${body}.${mac(body)}`;
}

function unseal<T>(token: string | undefined): T | undefined {
  if (!token) return undefined;
  const [body, tag] = token.split('.');
  if (!body || !tag) return undefined;
  const want = Buffer.from(mac(body));
  const got = Buffer.from(tag);
  if (want.length !== got.length || !timingSafeEqual(want, got)) return undefined;
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString()) as T;
  } catch {
    return undefined;
  }
}

function cookies(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) out[part.slice(0, eq).trim()] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return out;
}

// Secure only when the finish URI itself is https. An http finish, including localhost, is not.
let secureCookies = false;

function cookie(name: string, value: string, opts: { path?: string; maxAge?: number }): string {
  return [`${name}=${encodeURIComponent(value)}`, `Path=${opts.path ?? '/'}`, 'HttpOnly', 'SameSite=Lax',
    ...(secureCookies ? ['Secure'] : []), ...(opts.maxAge !== undefined ? [`Max-Age=${opts.maxAge}`] : [])].join('; ');
}

function accountsOf(req: IncomingMessage): Array<{ sid: string; session: Session }> {
  return accountsOfSet(cookies(req).aset);
}

function accountsOfSet(setId: string | undefined): Array<{ sid: string; session: Session }> {
  const out: Array<{ sid: string; session: Session }> = [];
  for (const sid of (setId && accountSets.get(setId)) || []) {
    const session = sessions.get(sid);
    if (!session) continue;
    if (session.expires <= Date.now()) {
      endSession(sid);
      void receiver?.untrack(sid);
      continue;
    }
    out.push({ sid, session });
  }
  return out;
}

function accountOf(req: IncomingMessage, account: string): { sid: string; session: Session } | undefined {
  return accountsOf(req).find((x) => x.session.account === account);
}

const samePerson = (a: Person, b: Person) => a.sub === b.sub && (a.iss ?? '') === (b.iss ?? '');

function send(res: ServerResponse, status: number, body: string | Buffer, headers: Record<string, string | string[]> = {}): void {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'content-security-policy': "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    ...headers,
  });
  res.end(body);
}

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title><link rel="stylesheet" href="/styles.css"></head>
<body><header><a href="/">gnap-caep-risc-nodejs demo</a></header><main>
${body}
</main><footer>A traditional web application signing in with GNAP through <a href="https://www.npmjs.com/package/gnap-caep-risc-nodejs">gnap-caep-risc-nodejs</a>.</footer></body>
</html>
`;
}

type Tab = 'identity' | 'events';

function tabs(base: string, active: Tab, count = 0): string {
  const tab = (id: Tab, label: string) =>
    `<a class="page-tab" role="tab" href="${base}/?tab=${id}" aria-selected="${id === active}"${id === active ? ' aria-current="page"' : ''}>${label}</a>`;
  return `<nav class="page-tabs" role="tablist" aria-label="Sections">${tab('identity', 'Identity')}${tab('events', `CAEP &amp; RISC events <span class="count" id="signal-count">${count || ''}</span>`)}</nav>`;
}

function member(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') {
    const values = Object.values(value as Record<string, unknown>);
    if (values.length && values.every((v) => typeof v === 'string')) return values.join(' / ');
    return JSON.stringify(value);
  }
  return String(value);
}

function logItem(e: LoggedEvent): string {
  const members = Object.entries(e.members)
    .filter(([k]) => k !== 'subject')
    .map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(member(v))}</td></tr>`).join('');
  const outcome = e.about === 'stream' ? 'about the stream: the verification this session asked for' : e.ended ? 'ended this session' : 'recorded; this session continues';
  return `<li class="log-item" data-id="${e.id}">
  <div class="log-top"><span class="badge ${e.family.toLowerCase()}">${e.family}</span> <strong>${esc(shortType(e.type))}</strong> <time>${esc(e.at)}</time></div>
  <p class="log-outcome${e.ended ? ' ended' : ''}">${esc(outcome)}</p>
  ${e.subject ? `<p><small>Subject: ${esc(e.subject)}</small></p>` : ''}
  ${members ? `<table class="facts members">${members}</table>` : ''}
  <p><small>jti ${esc(e.jti)}</small></p>
</li>`;
}

function eventsPanel(base: string, session: Session, notice?: string): string {
  const stream = receiver?.stream;
  const delivered = (stream?.events_delivered ?? []) as string[];
  const lastId = session.signals[0]?.id ?? 0;
  const gnap = tryClient();
  return `<section class="card">
<h2>Shared Signals stream</h2>
${notice ? `<p class="notice">${esc(notice)}</p>` : ''}
<table class="facts">
<tr><th>Receiver</th><td>${esc(receiverState)}</td></tr>
<tr><th>Stream status</th><td id="stream-status">${esc(streamStatus ? `${streamStatus.status} (${streamStatus.at})` : 'enabled')}</td></tr>
${stream ? `<tr><th>Stream</th><td>${esc(stream.stream_id)}<br><small>poll delivery (RFC 8936) at ${esc(stream.delivery?.endpoint_url)}</small></td></tr>
<tr><th>Authentication</th><td>${esc(proofPhrase(gnap))}</td></tr>
<tr><th>Delivers</th><td>${delivered.map((t) => `<span class="badge ${familyOf(t).toLowerCase()}">${familyOf(t)}</span> ${esc(shortType(t))}`).join('<br>') || '(nothing yet)'}</td></tr>` : ''}
<tr><th>Ends this session on</th><td>session-revoked, account-disabled, account-purged, credential-compromise, sessions-revoked</td></tr>
</table>
${stream ? `<form method="post" action="${base}/signals/verify" class="inline" id="verify-form"><button type="submit">Request verification event</button></form>` : ''}
</section>
<section class="card">
<h2>Event log</h2>
<p><small>The CAEP and RISC events about this session or its person, newest first, and the verification events this session asked for. Each appears here within moments of the receiver getting it: <span id="live-state">connecting…</span></small></p>
<ol class="log" id="log" data-last-id="${lastId}">${session.signals.map((e) => logItem(e)).join('')}</ol>
<p class="empty" id="log-empty"${session.signals.length ? ' hidden' : ''}>No CAEP or RISC event about this session yet. At the identity provider, change this person's password (credential-change), sign them out (session-revoked), or disable them (account-disabled), and watch this tab.</p>
<form method="post" action="${base}/signals/clear" class="inline"><button type="submit" class="secondary">Clear this session's log</button></form>
</section>`;
}

function accountBar(accounts: Array<{ session: Session }>, current: Session): string {
  const items = accounts.map(({ session: a }) => a === current
    ? `<li aria-current="true"><strong>${esc(who(a.person))}</strong></li>`
    : `<li><a href="/u/${esc(a.account)}/">${esc(who(a.person))}</a></li>`).join('');
  return `<nav class="accounts" aria-label="Accounts in this browser">
<span class="accounts-label">Signed in here:</span> <ul>${items}</ul>
<a class="button small" href="/login?add=1">Add another account</a>
${accounts.length > 1 ? '<form method="post" action="/logout" class="inline"><button type="submit" class="secondary small">Sign out of all accounts</button></form>' : ''}
</nav>`;
}

function claimRows(session: Session, gnap: GnapClient | undefined): string {
  const person = session.person;
  const username = person.uid || person.preferredUsername;
  const rows: Array<[string, string]> = [];
  if (username) rows.push(['Username', username]);
  rows.push(['Subject', person.sub]);
  if (person.iss) rows.push(['Issuer', person.iss]);
  if (person.email) rows.push(['Email', person.email]);
  if (person.name) rows.push(['Name', person.name]);
  if (person.preferredUsername && person.preferredUsername !== username) {
    rows.push(['Preferred username', person.preferredUsername]);
  }
  if (person.sid) rows.push(['Provider session', person.sid]);
  if (gnap) rows.push(['Key proof', gnap.security.keyProof]);
  rows.push(['Bound token', session.grant.bearer ? 'no' : 'yes']);
  if (session.grant.grantId) rows.push(['Grant', session.grant.grantId]);
  if (person.acr) rows.push(['acr', person.acr]);
  if (person.amr?.length) rows.push(['amr', person.amr.join(', ')]);
  rows.push(['ID token checked', person.assertionVerified ? 'yes' : 'no']);
  return rows.map(([name, value]) => `<tr><th>${esc(name)}</th><td>${esc(value)}</td></tr>`).join('');
}

function home(session: Session | undefined, gnap: GnapClient | undefined, problem?: string, tab: Tab = 'identity', notice?: string,
  accounts: Array<{ session: Session }> = [], gone?: string): string {
  if (session) {
    const base = `/u/${session.account}`;
    const identity = `<table class="facts">${claimRows(session, gnap)}</table>
<p><small>The access token, the continuation and the management token stay in this process. This page does not show them.</small></p>`;
    const count = session.signals.length;
    return page('Signed in', `<h1>Signed in as ${esc(who(session.person))}</h1>
${accountBar(accounts, session)}
${gone ? `<p class="notice">${esc(gone)}</p>` : ''}
${tabs(base, tab, count)}
<p id="signal-banner" class="problem" hidden></p>
<p id="signal-toast" class="notice" hidden></p>
<div role="tabpanel" id="panel" data-base="${base}" data-tab="${tab}" data-last-id="${session.signals[0]?.id ?? 0}">${tab === 'events' ? eventsPanel(base, session, notice) : identity}</div>
<form method="post" action="${base}/logout" class="inline"><button type="submit">Sign out of this account</button></form>
<script src="/app.js"></script>`);
  }
  return page('Sign in', `<h1>Sign in with GNAP</h1>
${problem ? `<p class="problem">${esc(problem)}</p>` : ''}
<p>This application is a GNAP client with a registered key${gnap ? ` (${esc(gnap.config.application)}, proved by ${esc(gnap.security.keyProof)})` : ''}.
The private key stays on the server. The browser is sent to the authorization server and comes back with an interaction hash;
the continuation token and the access token never pass through it. Tokens are key-bound.
iya-sts asks the client to wait before the continuation (<code>gnap.continueWaitS</code>, five seconds unless the realm changes it); this application waits at the callback.</p>
${gnap ? '<p class="buttons"><a class="button primary" href="/login">Sign in with GNAP</a></p>' : ''}`);
}

const SIGNED_IN_CSP = "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

interface PendingCookie {
  ids: string[];
  set?: string;
}

function explain(err: unknown): string {
  if (err instanceof GnapError) {
    const detail = err.gnapError ? `${err.gnapError}: ${err.message}` : `${err.code}: ${err.message}`;
    return detail;
  }
  return (err as Error).message;
}

async function placeSession(oldSetId: string | undefined, person: Person, grant: Grant): Promise<{ account: string; setCookie: string }> {
  if (sessions.size >= MAX_SESSIONS) {
    for (const [k, s] of sessions) if (s.expires <= Date.now()) sessions.delete(k);
  }
  if (sessions.size >= MAX_SESSIONS) throw new Error('too many sessions');
  const sid = randomBytes(32).toString('base64url');
  const until = Date.now() + SESSION_MS;
  const accounts = accountsOfSet(oldSetId);
  const shown = personWithAccessTokenUid(person, grant.accessToken);
  const existing = accounts.find((a) => samePerson(a.session.person, shown));
  const account = existing?.session.account ?? randomBytes(9).toString('base64url');
  if (existing) {
    endSession(existing.sid);
    await receiver?.untrack(existing.sid);
    tell(existing.sid, 'replaced', {});
  }
  const setId = randomBytes(32).toString('base64url');
  const order = accounts.map((a) => (a.sid === existing?.sid ? sid : a.sid));
  if (!existing) order.push(sid);
  if (oldSetId) accountSets.delete(oldSetId);
  accountSets.set(setId, order);
  for (const x of order) {
    const s = x === sid ? undefined : sessions.get(x);
    if (s) s.setId = setId;
  }
  sessions.set(sid, { person: shown, grant, expires: until, signals: [], setId, account });
  rememberGrant(grant);
  await watch(sid, shown, until);
  console.log(`signed in ${who(shown)} (${shown.sub}); ${order.length} account(s) in this browser`);
  const longest = Math.max(...order.map((x) => sessions.get(x)?.expires ?? 0));
  return { account, setCookie: cookie('aset', setId, { maxAge: Math.floor((longest - Date.now()) / 1000) }) };
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolveBody, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > 1_000_000) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolveBody(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://demo.invalid');
  const method = req.method ?? 'GET';

  if (url.pathname === '/healthz') return send(res, 200, 'ok', { 'content-type': 'text/plain' });
  if (url.pathname === '/styles.css') return send(res, 200, STYLES, { 'content-type': 'text/css; charset=utf-8', 'cache-control': 'max-age=300' });
  if (url.pathname === '/app.js') return send(res, 200, APP_JS, { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'max-age=300' });

  const scoped = /^\/u\/([A-Za-z0-9_-]{6,32})(\/.*)?$/.exec(url.pathname);
  const hereAccount = scoped ? accountOf(req, scoped[1] ?? '') : undefined;
  const sub = scoped ? (scoped[2] ?? '/') : undefined;

  if (scoped && !hereAccount) {
    if (sub === '/api/signals') return send(res, 401, JSON.stringify({ signedIn: false }), { 'content-type': 'application/json', 'cache-control': 'no-store' });
    if (sub === '/events') return send(res, 204, '');
    res.writeHead(303, { location: '/?gone=1', 'cache-control': 'no-store' });
    res.end();
    return;
  }

  if (hereAccount && sub === '/events' && method === 'GET') {
    const sid = hereAccount.sid;
    res.writeHead(200, {
      'content-type': 'text/event-stream', 'cache-control': 'no-store', 'x-accel-buffering': 'no', 'referrer-policy': 'no-referrer',
    });
    const after = Number(req.headers['last-event-id'] ?? url.searchParams.get('after') ?? 0) || 0;
    res.write('retry: 2000\n\n');
    for (const e of [...hereAccount.session.signals].reverse()) if (e.id > after) res.write(`id: ${e.id}\nevent: signal\ndata: ${JSON.stringify(e)}\n\n`);
    if (streamStatus) res.write(`event: stream\ndata: ${JSON.stringify(streamStatus)}\n\n`);
    const set = listeners.get(sid) ?? new Set<ServerResponse>();
    set.add(res);
    listeners.set(sid, set);
    const keepAlive = setInterval(() => res.write(': keep-alive\n\n'), 20_000);
    req.on('close', () => {
      clearInterval(keepAlive);
      set.delete(res);
      if (!set.size) listeners.delete(sid);
    });
    return;
  }

  if (hereAccount && sub === '/api/signals' && method === 'GET') {
    const session = hereAccount.session;
    const after = Number(url.searchParams.get('after') ?? 0) || 0;
    const events = [...session.signals].reverse().filter((e) => e.id > after);
    return send(res, 200, JSON.stringify({ signedIn: true, events, lastId: session.signals[0]?.id ?? after, streamStatus: streamStatus ?? null }), { 'content-type': 'application/json', 'cache-control': 'no-store' });
  }

  if (url.pathname === '/' && method === 'GET') {
    const first = accountsOf(req)[0];
    if (first) {
      res.writeHead(303, { location: `/u/${first.session.account}/${url.searchParams.get('gone') ? '?gone=1' : ''}`, 'cache-control': 'no-store' });
      res.end();
      return;
    }
  }

  if ((url.pathname === '/' || (hereAccount && sub === '/')) && method === 'GET') {
    const session = hereAccount?.session;
    const gnap = tryClient();
    const problem = gnap ? undefined : `The GNAP client is not configured yet: ${gnapError ?? 'the key could not be read'}. Run npm run generate-key, then npm run configure-iya-sts.`;
    const tab = url.searchParams.get('tab') === 'events' ? 'events' : 'identity';
    const notice = url.searchParams.get('verify') === 'sent'
      ? 'Verification event requested; it shows in the log within a few seconds.'
      : url.searchParams.get('verify') === 'failed' ? 'The transmitter refused the verification request; see the demo\'s log.' : undefined;
    const gone = url.searchParams.get('gone') ? 'The account you opened is no longer signed in here.' : undefined;
    return send(res, 200, home(session, gnap, gone && !session ? gone : problem, tab, notice, accountsOf(req), gone), session ? {
      'content-security-policy': SIGNED_IN_CSP,
    } : {});
  }

  if (url.pathname === '/login' && method === 'GET') {
    try {
      const gnap = client();
      const again = url.searchParams.get('account') ? accountOf(req, url.searchParams.get('account')!) : undefined;
      const person = again?.session.person;
      const started = await gnap.requestGrant({
        ...(person?.sub ? { expectedSub: person.sub } : {}),
        ...(person?.sub && person.iss ? { user: { sub_ids: [{ format: 'iss_sub', iss: person.iss, sub: person.sub }] } } : {}),
      });
      if ('grant' in started) {
        const placed = await placeSession(cookies(req).aset, started.grant.subject ?? { sub: 'unknown', claims: {}, assertionVerified: false }, started.grant);
        res.writeHead(303, { location: `/u/${placed.account}/`, 'set-cookie': placed.setCookie, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
        res.end();
        return;
      }
      const before = unseal<PendingCookie>(cookies(req).gpending)?.ids ?? [];
      const ids = [started.pending.id, ...before].slice(0, 3);
      const setNow = cookies(req).aset;
      const pending = cookie('gpending', sealed({ ids, ...(setNow && accountSets.has(setNow) ? { set: setNow } : {}) }), { path: '/callback', maxAge: 600 });
      res.writeHead(302, { location: started.redirectUrl, 'set-cookie': pending, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
      res.end();
    } catch (err) {
      const what = explain(err);
      console.warn(`sign-in did not start: ${what}`);
      send(res, 400, page('Sign-in failed', `<h1>Sign-in failed</h1><p class="problem">${esc(what)}</p><p><a href="/">Start again</a></p>`));
    }
    return;
  }

  if (url.pathname === '/callback' && method === 'GET') {
    const gnap = client();
    const pending = unseal<PendingCookie>(cookies(req).gpending);
    const clearPending = cookie('gpending', '', { path: '/callback', maxAge: 0 });
    try {
      const done = await gnap.finishRedirect(url.searchParams, { allowedIds: pending?.ids ?? [] });
      if (!done.grant.subject) throw new GnapError('validation', 'the grant has no subject');
      const placed = await placeSession(pending?.set ?? cookies(req).aset, done.grant.subject, done.grant);
      res.writeHead(303, {
        location: `/u/${placed.account}/`,
        'set-cookie': [clearPending, placed.setCookie],
        'cache-control': 'no-store',
        'referrer-policy': 'no-referrer',
      });
      res.end();
    } catch (err) {
      const what = explain(err);
      console.warn(`sign-in refused: ${what}`);
      send(res, 400, page('Sign-in failed', `<h1>Sign-in failed</h1><p class="problem">${esc(what)}</p><p><a href="/">Start again</a></p>`), { 'set-cookie': clearPending });
    }
    return;
  }

  if (url.pathname === '/gnap/push' && method === 'POST') {
    try {
      const gnap = client();
      const text = await readBody(req);
      const done = await gnap.finishPush(text ? JSON.parse(text) as unknown : undefined);
      if (done.grant.subject) rememberGrant(done.grant);
      res.writeHead(204, { 'cache-control': 'no-store' });
      res.end();
    } catch (err) {
      const what = explain(err);
      console.warn(`push finish refused: ${what}`);
      send(res, 400, JSON.stringify({ error: what }), { 'content-type': 'application/json' });
    }
    return;
  }

  if (hereAccount && sub === '/signals/verify' && method === 'POST') {
    let outcome = 'failed';
    const sid = hereAccount.sid;
    if (receiver?.stream) {
      try {
        const state = randomBytes(12).toString('base64url');
        verificationsAsked.set(state, sid);
        if (verificationsAsked.size > 1000) verificationsAsked.delete(verificationsAsked.keys().next().value!);
        await receiver.verify(state);
        outcome = 'sent';
      } catch (err) {
        console.warn(`ssf: verification request refused: ${(err as Error).message}`);
      }
    }
    if (String(req.headers.accept ?? '').includes('application/json')) {
      return send(res, outcome === 'sent' ? 202 : 502, JSON.stringify({ outcome }), { 'content-type': 'application/json', 'cache-control': 'no-store' });
    }
    res.writeHead(303, { location: `/u/${hereAccount.session.account}/?tab=events&verify=${outcome}`, 'cache-control': 'no-store' });
    res.end();
    return;
  }

  if (hereAccount && sub === '/signals/clear' && method === 'POST') {
    hereAccount.session.signals = [];
    res.writeHead(303, { location: `/u/${hereAccount.session.account}/?tab=events`, 'cache-control': 'no-store' });
    res.end();
    return;
  }

  if (hereAccount && sub === '/logout' && method === 'POST') {
    endSession(hereAccount.sid);
    await receiver?.untrack(hereAccount.sid);
    tell(hereAccount.sid, 'signed-out', {});
    res.writeHead(303, { location: '/', 'cache-control': 'no-store' });
    res.end();
    return;
  }

  if (url.pathname === '/logout' && method === 'POST') {
    for (const { sid } of accountsOf(req)) {
      endSession(sid);
      await receiver?.untrack(sid);
      tell(sid, 'signed-out', {});
    }
    res.writeHead(303, { location: '/', 'set-cookie': cookie('aset', '', { maxAge: 0 }), 'cache-control': 'no-store' });
    res.end();
    return;
  }

  send(res, 404, page('Not found', '<h1>Not found</h1>'));
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((err: Error) => {
    console.error(err);
    if (!res.headersSent) send(res, 500, page('Error', `<h1>Something went wrong</h1><p class="problem">${esc(err.message)}</p><p><a href="/">Home</a></p>`));
    else res.end();
  });
});

try {
  const finishUri = readConfig().finishUri;
  secureCookies = new URL(typeof finishUri === 'string' && finishUri ? finishUri : 'http://localhost/callback').protocol === 'https:';
} catch (err) {
  console.warn(`cannot read ${CONFIG}: ${(err as Error).message}`);
}

server.listen(PORT, () => console.log(`gnap-caep-risc-nodejs demo on port ${PORT}, configuration ${CONFIG}`));
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    receiver?.stop();
    server.close(() => process.exit(0));
  });
}
