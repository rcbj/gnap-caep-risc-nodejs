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

Those management calls do not verify TLS (`rejectUnauthorized` false). A development iya-sts presents a certificate node does not trust yet. The demo does not do that: the script saves the whole chain the handshake presented, leaf through root, to `demo/generated/idp-ca.pem`, and prints the leaf's SHA-256 fingerprint. Compare that fingerprint with the certificate on iya-sts's main port before you rely on the file.

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

No `class_id` is registered, and no browser origin. This client is a server. A re-run that finds the application already in the registry adds the finish URI, the start mode, the scopes and the bearer flag. It does not send `gnapKey` again. A new key means a new registration, or setting `gnapKey` yourself.

It also turns on `authn.multipleAccounts`. GNAP's account hint is soft, and a second sign-in in the same browser ends the first provider session unless the realm allows more than one. The test user is `gnap-demo-user`, in the groups `ssf-read` and `ssf-manage`. The password is `GNAP_DEMO_USER_PASSWORD`, or one is generated and printed once. The application is added to the roles `SSF_READ` and `SSF_MANAGE`.

`--idp https://host/realm/acme` targets that realm. Anything else after the host is refused. With no `--idp`, the grant endpoint's origin is used, and a trailing `/gnap` is not part of the realm.
