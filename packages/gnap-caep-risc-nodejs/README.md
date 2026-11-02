# gnap-caep-risc-nodejs

A server-side [GNAP](https://www.rfc-editor.org/rfc/rfc9635) client for a traditional Node.js web application, and a CAEP and RISC Shared Signals receiver. TypeScript, usable from JavaScript, no runtime dependency.

The overlapping configuration names match [gnap-caep-js](https://github.com/rcbj/gnap-caep-js). That library runs in a browser and sends a `class_id`. This one holds the private key, registers it, and proves it with mutual TLS, an HTTP message signature, or a detached JWS.

```ts
import { GnapClient } from 'gnap-caep-risc-nodejs';

const gnap = GnapClient.fromFile('gnap.json');
const started = await gnap.requestGrant();
const done = await gnap.finishRedirect(query, { allowedIds });
```

The walkthrough is [the server-side guide](docs/guide.md). Events are [Handling CAEP and RISC events](docs/signals.md). The license is the [MIT License](LICENSE).

## Configuration

| Field | |
|---|---|
| `grantEndpoint` | Required. `https://idp.example/gnap`. `http` only with `allowInsecure`. |
| `application` | Required. The registered application's identifier. Not sent as `class_id`. Also accepted as an ID token audience. |
| `privateKey` | Required. PEM PKCS#8, `file:path`, `env:NAME`, or a path. |
| `transmitterIssuer` | gnap-caep-js's name for the Shared Signals issuer. `ssf.transmitter` wins when both are set. Ignored when `signals` is false. |
| `idTokenIssuer` | Issuer of subject ID tokens. Defaults to the grant endpoint's origin. |
| `classId` | Optional. Sent as `client.class_id` only when set. The demo does not set it. |
| `display` | `{ name, uri }`, sent with the key on the first grant. |
| `access` | Rights. Default `ssf.read` and `ssf.manage`. `signals: false` removes those two. |
| `signals` | CAEP and RISC. Default on (omitted or `true`). `false` turns them off. |
| `subIdFormats` | Default `iss_sub`, `account`, `opaque`. Filtered to what the grant server advertises. |
| `assertionFormats` | Default `id_token`. |
| `keyProof` | `mtls`, `httpsig`, or `jwsd`. Default `mtls` when `certificate` is set, otherwise `httpsig`. |
| `certificate` | PEM. Required for mutual TLS. A chain is leaf first: the key is the leaf, and the handshake sends the whole chain. |
| `finishUri` | Redirect or push target. Loopback `http` is allowed. |
| `finishMethod` | `redirect` (default) or `push`. |
| `interactionStart` | Default `["redirect"]`. |
| `hashMethod` | Only `sha-256`. Omitted from the request, which is the default method. |
| `requireBoundTokens` | Default true. A `bearer` flag is then an error. |
| `useInstanceId` | Default true. After the first response, `client` is the instance id string. |
| `tlsCa` | CA trust chain for the authorization server's TLS listener. PEM, `file:path`, `env:NAME`, or a path, trusted in addition to node's own store. A missing file is ignored. |
| `allowInsecure` | Allow an `http` grant endpoint and a non-loopback `http` finish URI. Default false. |
| `clockToleranceSec` | ID token skew. Default 30. |
| `maxWaitSec` | The longest one continuation may be delayed by `continue.wait` or `too_fast`. Default 30. |
| `transactionTtlSec` | How long a pending interaction is kept. Default 600. |
| `ssf.transmitter` | The transmitter's issuer. Not used when `signals` is false. |
| `ssf.pollIntervalMs` | Pause between polls when nothing else is waiting. The receiver's own default is 5000. |

`signals` defaults to on. Omitted is the same as `true`, and the resolved configuration leaves the flag out. `signals: false` turns CAEP and RISC off. It drops the rights `ssf.read` and `ssf.manage` (a string is trimmed first; an object is dropped only when `type` is exactly one of those two) and does not fill `ssf`, so the client does not require transmitter metadata and does not fetch `/.well-known/ssf-configuration`. The grant's subject request is unchanged. If those two were the only rights, set `access` to a right the authorization server grants. The resolved configuration includes `signals: false` only in that case. Callers test `config.signals !== false`.

`GnapClient.fromFile(path)` reads the file and the key. It does not discover. `GnapClient.resolve(object, baseDir)` and `GnapClient.create(resolved)` build one from an object. Relative paths start at `baseDir`, which for a file is the file's directory.

## Grant

`requestGrant({ access, user, expectedSub, context, subject })` returns `{ redirectUrl, pending }` or `{ grant }` when the server issues the token immediately. Keep `pending.id` with the browser. The continuation token stays here.

`finishRedirect(query, { allowedIds })` completes a redirect. `allowedIds` is required. An id that is not in it does not consume the pending. The hash is single use and compared in constant time. A front-channel token (`access_token`, `id_token`, `token`, `value`, `continue`, `refresh_token`) is refused. Duplicate query parameters are refused.

`finishPush(body)` completes `{ hash, interact_ref }` posted by the authorization server. The hash is the authenticator; there is no `allowedIds`.

`authorizationHeaders(grant, { method, url, body })` returns `Authorization: GNAP` and the proof headers. Pass the exact body that will be sent. `call` sends that request. `rotate` posts to the manage URI. `revoke` deletes the continuation URI. `ensureFresh` rotates when `expiresAt` is within 60 seconds or already past.

`tls()` is `ca`, and for mutual TLS the certificate and the PKCS#8 key. `security` describes the posture. `instanceId` is set from the first response that carries one.

A `continue` or `manage` URI on another origin, or one with user information (`user:password@`), throws before the request is sent. `too_fast` adopts the continuation in the error body, waits, and retries inside `maxWaitSec`. A zero wait is retried at most twice.

## Subject

An `id_token` assertion is verified against the issuer's JWKS: `iss` equals `idTokenIssuer`, `sub` and `exp` are present, the times sit inside the skew, and `aud` intersects the instance id and the application identifier when either is known. `iss_sub.sub` must equal the token's `sub`. HMAC and `none` are refused. Without an `id_token`, `sub` falls back to an opaque id and then an account URI, and `assertionVerified` is false.

## Errors

`GnapError` has `code` (`config`, `discovery`, `protocol`, `validation`, `signature`, `ssf`) and, when the authorization server named one, `gnapError` (`user_denied`, `too_fast`, …). `continuation` is the handle from a `too_fast` body. `context` is whatever `requestGrant` was given, on a finish that fails after the pending was found.

## Shared Signals

With `signals` left on, `SignalsReceiver` polls one stream. `signals: false` does not start it and does not contact a transmitter. `SignalsReceiver` stays exported for a caller that builds one itself. `headers` receives `{ method, url, body }` so the proof covers the body. `track` / `untrack` maintain the session index. `on(type, handler)` and `on('*')` see each verified event. `endOn` defaults to session-revoked, account-disabled, account-purged, credential-compromise, and sessions-revoked. `verify(state)` asks for a verification event.

`EVENT`, `CAEP_EVENTS`, `RISC_EVENTS`, `DEFAULT_EVENTS_REQUESTED`, and `DEFAULT_ENDING_EVENTS` are the event URIs. `MemorySessionIndex` is the default index. `trackedFromPerson` builds a row from a GNAP subject.

## Key generation

```sh
npx gnap-caep-risc-nodejs generate-key --config gnap.json [--cn name] [--days 1095] [--force]
```

P-256, PKCS#8, and a self-signed certificate. Existing files are kept unless `--force` is set.
