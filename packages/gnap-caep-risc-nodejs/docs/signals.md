# Handling CAEP and RISC events

A GNAP application owns one Shared Signals stream. iya-sts scopes that stream to the people who approved a grant to the application. The receiver polls it ([RFC 8936](https://www.rfc-editor.org/rfc/rfc8936)) and turns an event into the application's own sessions.

The rights are the strings `ssf.read` and `ssf.manage`. iya-sts grants them only when the application's `oauthAllowedScope` declares them, and the person approves them. Put the application in the roles `SSF_READ` and `SSF_MANAGE` as well. [`scripts/configure-iya-sts.ts`](../../../scripts/configure-iya-sts.ts) does both.

`signals` defaults to on, so an existing configuration keeps receiving events. `signals: false` turns CAEP and RISC off. The client then drops `ssf.read` and `ssf.manage`, does not require transmitter metadata, does not fetch `/.well-known/ssf-configuration`, and does not start `SignalsReceiver`. The grant's subject request is unchanged. If those two were the only access rights, set `access` to a right the authorization server grants. `SignalsReceiver` stays exported. The setup script also ignores those two rights when the flag is false, and does not require a transmitter.

## Authentication

Every management call and every poll presents a GNAP access token and the key proof:

```ts
import { GnapClient, SignalsReceiver, trackedFromPerson } from 'gnap-caep-risc-nodejs';

const gnap = GnapClient.fromFile('gnap.json');
// grant is a key-bound access token from a finished grant. Keep one after the browser signs out,
// so the stream still has a token.

const receiver = new SignalsReceiver({
  transmitter: gnap.config.ssf!.transmitter,
  tls: gnap.tls(),
  headers: async (request) => gnap.authorizationHeaders(grant, request),
  onEndSessions: (ids) => { /* end these local sessions */ },
});
```

`headers` is given `{ method, url, body }`. `body` is the exact JSON that will be sent, so an HTTP message signature or a detached JWS can cover its Content-Digest. Mutual TLS adds no signature header; the certificate is on `tls`. Pass the same `tls` the grant client uses.

Start the receiver after a grant exists. Starting it when the process loads makes the home page depend on the transmitter, and a health check would poll an authorization server that may not be there.

## What it asks for

The default set is the CAEP session and credential events and the RISC account events, plus SSF's own verification and stream-updated events when the transmitter delivers them. The list is `DEFAULT_EVENTS_REQUESTED`. Override it with `eventsRequested`.

An event ends the matching local sessions when its type is in `endOn`. The default, `DEFAULT_ENDING_EVENTS`, is:

- `session-revoked`
- `account-disabled`
- `account-purged`
- `credential-compromise`
- `sessions-revoked` (RISC, deprecated in favour of CAEP's session-revoked, and still ended)

Anything else is delivered to `receiver.on(type, handler)` and to `on('*')`, and the session continues. A `credential-change` is recorded. It does not end the session.

## How a session is matched

`track` after each sign-in. `trackedFromPerson` copies the GNAP subject's `sub`, email and `sid` (the provider session, from the ID token's `sid` or `session_id`).

A session event that names a provider session ends only the local sessions started from that provider session. Any other event ends every local session of that person, matched by subject and then by email. A verification event and a stream-updated event match nobody: the first is tied to the `state` this process sent to `verify`, and the second updates the stream, not a person.

The default index is this process's memory. Several processes need one shared `SessionIndex`, or an event received on one process cannot end a session another process created.

## What is checked before an event counts

The transmitter's configuration is read from `/.well-known/ssf-configuration`, inserted into the issuer path and then appended if that misses. Poll delivery has to be offered. Each SET is verified against the transmitter's JWKS before it is acted on: signature, `iss`, `aud` (the stream's audience), and `typ` when it is present. HMAC and `none` are refused. A SET that fails verification is acknowledged with `setErrs` and `invalid_key`, not handled twice. A SET that was handled is acknowledged on the next poll, including when the application's own handler throws.

`pollIntervalMs` is how long to wait when the poll was not told that more is waiting. The demo uses 3000. The default is 5000.
