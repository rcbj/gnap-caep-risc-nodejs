# Adding GNAP sign-in to a server-side web application

This walks through a traditional, server-rendered application: the configuration, the key, the login route, and the callback. The [demo](../../../demo/server.ts) is all of it in one file with `node:http`.

The private key stays in the server process. The browser carries an interaction hash and an `interact_ref`. Tokens stay in the server, and the pages do not render them.

## 1. The configuration

The names that [gnap-caep-js](https://github.com/rcbj/gnap-caep-js) already uses mean the same thing here: `grantEndpoint`, `transmitterIssuer`, `idTokenIssuer`, `application`, `display`, `access`, `subIdFormats`, `assertionFormats`.

`application` is the registered application's identifier. It is **not** sent as `class_id`. A server holds the private key, so the key itself is what iya-sts registers. Set `classId` only when you deliberately want an unregistered instance's class, which this library's demo does not.

```json
{
  "grantEndpoint": "https://idp.example/gnap",
  "transmitterIssuer": "https://idp.example",
  "idTokenIssuer": "https://idp.example",
  "application": "app",
  "display": { "name": "App", "uri": "https://app.example/" },
  "access": ["ssf.read", "ssf.manage"],
  "subIdFormats": ["iss_sub", "account", "opaque"],
  "assertionFormats": ["id_token"],
  "keyProof": "mtls",
  "privateKey": "file:keys/client.key",
  "certificate": "file:keys/client.crt",
  "finishUri": "https://app.example/callback",
  "finishMethod": "redirect",
  "interactionStart": ["redirect"],
  "tlsCa": "keys/idp-ca.pem",
  "ssf": { "transmitter": "https://idp.example", "pollIntervalMs": 3000 }
}
```

`signals` defaults to on. Leave it out, or set `true`, and the client keeps receiving CAEP and RISC events: access defaults to `ssf.read` and `ssf.manage`, and `ssf` is filled from `ssf.transmitter` or `transmitterIssuer`. Set `signals` to `false` when the authorization server does not implement Shared Signals. That drops those two rights, does not fill `ssf`, and does not contact a transmitter, including `/.well-known/ssf-configuration`. The subject request is unchanged. If `access` was only those two rights, set it to a right the authorization server grants. The resolved configuration omits `signals` when it is on and includes `signals: false` only when it is off.

`keyProof` is `mtls`, `httpsig`, or `jwsd`. When it is omitted, a certificate selects mutual TLS and anything else selects HTTP message signatures. `tlsCa` is the CA trust chain for the authorization server's TLS listener: a PEM bundle, `file:path`, `env:NAME`, or a path. iya-sts publishes that bundle at `GET /tls/server-certificate`. A missing file is ignored, so the process can still serve a page before the file exists.

For iya-sts, [`scripts/configure-iya-sts.ts`](../../../scripts/configure-iya-sts.ts) registers the application and saves the listener CA trust chain into the file `tlsCa` names. The demo container refreshes that file when it starts.

`privateKey` and `certificate` are PEM, `file:path` (next to the configuration), `env:NAME`, or a filesystem path. Keep the private key out of the image and out of version control. `certificate` may be a chain, leaf first: the grant request names the leaf, and mutual TLS presents the whole chain.

`hashMethod` accepts only `sha-256`, which is the default, and it is left out of the grant request. `requireBoundTokens` defaults to true. `useInstanceId` defaults to true: after the first response, later grant requests send `client` as that instance id string, still proved by the same key.

A loopback `http` finish URI is allowed. The grant endpoint must be `https` unless `allowInsecure` is true. Mutual TLS requires an `https` grant endpoint. A push finish that iya-sts will dial has to be `https` as well (`gnap.pushAllowHttp` is false there); the demo uses redirect so it can finish on `http://localhost`.

For iya-sts, [`scripts/configure-iya-sts.ts`](../../../scripts/configure-iya-sts.ts) registers the application and saves the provider's TLS chain. [`generate-key`](../../../packages/gnap-caep-risc-nodejs/src/cli.ts) writes the P-256 key and the self-signed certificate the mutual TLS proof presents.

## 2. The key

```sh
npx gnap-caep-risc-nodejs generate-key --config gnap.json --cn localhost
```

That writes PKCS#8 and a certificate at the `file:` paths. An existing key is left alone unless `--force` is given. The certificate's public key is the private key's. Mutual TLS registers `{"proof":"mtls","cert":"<PEM>"}`. iya-sts accepts that PEM (it also accepts raw base64 DER). In development, `gnap.mtlsTrust` `auto` is pinned: the registered certificate is the key, and a self-signed one is enough. Do not add it to the client truststore for that model. In product mode the same setting is `pki`, and the certificate has to chain to the realm's authority.

HTTP message signatures and detached JWS register a JWK instead. `kid` is the RFC 7638 thumbprint, and `alg` is set. The signature covers `@method`, `@target-uri`, `content-digest` when there is a body, and `authorization` when a token is presented. There is no `alg` signature parameter. The `keyid` is the JWK `kid`, and the tag is `gnap`. ECDSA signatures are raw R||S. A detached JWS uses the header name `detached-jws`, `typ` `gnap-binding-jwsd`, and signs the hash of the body once. `ath` is the hash of the token value, not of the whole Authorization header.

## 3. The login route

```ts
import { GnapClient } from 'gnap-caep-risc-nodejs';

const gnap = GnapClient.fromFile('gnap.json');

// GET /login
const started = await gnap.requestGrant();
if ('redirectUrl' in started) {
  // Store started.pending.id with this browser (an httpOnly cookie is enough).
  // Redirect the browser to started.redirectUrl.
}
```

`fromFile` does not contact the authorization server. Discovery is an OPTIONS on the grant endpoint, and it runs on `requestGrant`. The client refuses a key proof or a finish method the server does not list, and it drops subject formats the server does not advertise. `grant_request_endpoint` has to be the endpoint that was asked.

The first request sends the key by value, with `display` when the file has one. It asks for the configured access rights and for subject identifiers and an `id_token`. The interaction finish nonce is random and stays in this process.

To sign the same person in again, pass a hint and the subject you expect. GNAP has no `ForceAuthn`; iya-sts treats an account hint as soft, so the realm has to allow more than one account (`authn.multipleAccounts`) or the second sign-in replaces the first at the provider.

```ts
await gnap.requestGrant({
  expectedSub: person.sub,
  user: { sub_ids: [{ format: 'iss_sub', iss: person.iss, sub: person.sub }] },
});
```

## 4. The callback

```ts
// GET /callback?hash=…&interact_ref=…
const done = await gnap.finishRedirect(query, { allowedIds });
```

`allowedIds` are the pending ids this browser's cookie names. A redirect URL from another browser does not match, and the pending is not consumed. The hash is compared in constant time and is single use. A repeated parameter is refused. `access_token`, `id_token`, `value`, `continue`, or `refresh_token` in the query is refused: GNAP does not deliver tokens on the front channel.

The continuation is `POST` to `continue.uri` with `Authorization: GNAP` and the key proof, body `{ "interact_ref": "…" }`. iya-sts may answer `too_fast` and include a new continuation. The client waits out `continue.wait` (what is left of it, since the person already spent some of it at the provider), bounded by `maxWaitSec` (30). A zero wait is retried only twice. A `continue` or `manage` URI on another origin, or one with user information (`user:password@`), is refused before anything is fetched.

The subject `id_token` is checked with `node:crypto`: issuer, `exp` / `nbf` / `iat` within `clockToleranceSec`, signature, and audience. iya-sts puts the **instance id** in the audience. This client also accepts the application identifier. HMAC and `none` are refused. If `iss_sub.sub` and the token's `sub` differ, the grant is refused.

A push finish is `finishPush` on the JSON body the authorization server posts. There is no cookie; the hash is the authenticator. The demo's route is `POST /gnap/push`. The demo itself uses redirect.

## 5. Using the token

```ts
const headers = gnap.authorizationHeaders(done.grant, { method: 'GET', url });
// or
const answer = await gnap.call(done.grant, url);

const fresh = await gnap.ensureFresh(done.grant);   // rotates when expiry is within 60 seconds
await gnap.revoke(fresh);                           // DELETE the continuation; 204 is success
```

Rotation is `POST` to the manage URI with the management token and no body ([RFC 9635 section 6.1](https://www.rfc-editor.org/rfc/rfc9635#section-6.1)). The subject and the continuation carry over when the response omits them. A rotation that comes back `bearer` is refused. Revocation is `DELETE` on the continuation URI ([section 5.4](https://www.rfc-editor.org/rfc/rfc9635#section-5.4)).

`gnap.tls()` is the trust and, for mutual TLS, the client certificate. Present that certificate on every call to the authorization server, including discovery and the Shared Signals transmitter.

What a caller can show is `gnap.security`: the proof, that tokens are bound, the finish method, and that the key is registered and the interaction hash is required.
