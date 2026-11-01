---
title: Setting up iya-sts
---

# Setting up iya-sts

`scripts/configure-iya-sts.ts` registers the demo as a GNAP client of a running [iya-sts](https://rcbj.github.io/iya-sts/). The grant endpoint in `demo/gnap.json` is `https://localhost:8081/gnap`. What iya-sts stores for a GNAP application is described in [Configure a GNAP application](https://rcbj.github.io/iya-sts/configure-gnap.html).

```sh
npm run generate-key -- --config demo/gnap.json --cn localhost
ADMIN_API_CLIENT_SECRET=… npm run configure-iya-sts
node scripts/configure-iya-sts.ts --dry-run
```

The token is minted the way iya-sts's own tools mint one: the seeded client `sts-api-client`, grant `client_credentials`, HTTP Basic, audience `<base>/admin-api`, scope `admin:read admin:write`. The secret is `ADMIN_API_CLIENT_SECRET` or `STS_ADMIN_API_CLIENT_SECRET`. On a compose stack that secret is in OpenBao; iya-sts's management API docs say how to read it.

Those management calls do not verify TLS (`rejectUnauthorized` false). The demo does not do that.

## TLS

`tlsCa` in the configuration is the CA trust chain for the STS listener certificate. The demo's file names `demo/generated/idp-ca.pem`. Every run rewrites that file from `GET /tls/server-certificate`: the listener certificate, the intermediates, and the root. That is the bundle iya-sts tells a client to trust. The first fetch does not verify TLS, because there is nothing to verify it against until the file exists. If that document is not served, the script saves the chain the handshake presented instead.

The script prints the trust anchor's SHA-256 fingerprint. Compare it with the Root CA on iya-sts's Server configuration, PKI page. A certified listener certificate on its own is not an anchor: the chain has to include the root that signed it. Later calls trust this file in addition to node's own store. An inline PEM or an `env:` value is left as the parameter.

## What it registers

The application id is the file's `application` (`gnap-caep-risc-demo`). The kind is `gnap-client`. The protocol is `gnap`. The fields are:

| Field | Value |
|---|---|
| `gnapKey` | the public key, one JSON string. Mutual TLS is `{"proof":"mtls","cert":"<PEM>"}`. Sent only when the application is created |
| `gnapFinishUri` | the file's `finishUri` (`http://localhost:3000/callback`) |
| `gnapInteractionStartModes` | `redirect` |
| `gnapBearerTokens` | `FALSE`, so iya-sts refuses a `bearer` flag for this client |
| `gnapDisplayUri` | the file's `display.uri` |
| `oauthAllowedScope` | the string rights in `access`, `ssf.read` and `ssf.manage` |

No `class_id` is registered, and no browser origin. This client is a server. A re-run that finds the application already in the registry adds the finish URI, the start mode and the scopes, and sets the bearer flag and the display URI. A single-valued field goes through `applications/set`; `applications/add` refuses it. The re-run does not send `gnapKey` again. A new key means a new registration, or setting `gnapKey` yourself.

It also turns on `authn.multipleAccounts`. GNAP's account hint is soft, and a second sign-in in the same browser ends the first provider session unless the realm allows more than one. The test user is `gnap-demo-user`, in the groups `ssf-read` and `ssf-manage`. The password is `GNAP_DEMO_USER_PASSWORD`, or one is generated and printed once. The application is added to the roles `SSF_READ` and `SSF_MANAGE`.

Every run sets one custom claim on the application's GNAP access-token JWT: the name `uid`, the value `${username}`. iya-sts expands that to the directory username when it mints a `jwt-signed` token (and the JWT inside a `jwt-encrypted` one). The demo heading reads that claim. A re-run replaces the row of the same name.

`--idp https://host/realm/acme` targets that realm. Anything else after the host is refused. With no `--idp`, the grant endpoint's origin is used, and a trailing `/gnap` is not part of the realm.
