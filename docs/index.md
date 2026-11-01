---
title: gnap-caep-risc-nodejs
---

# gnap-caep-risc-nodejs

A **server-side GNAP client** ([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635)) for a traditional Node.js web application: the server renders the pages and holds the key. It is the counterpart of [gnap-caep-js](https://github.com/rcbj/gnap-caep-js), which runs in a browser. A browser cannot hold a registered private key, so that library uses a `class_id`. This one registers the key and uses the proofs a server can present.

- **A registered key**, sent by value on the first grant and as an `instance_id` after that. It is not a per-browser class.
- **Key proof** by mutual TLS, an HTTP message signature ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)), or a detached JWS. The demo uses mutual TLS, which a page cannot present.
- **Key-bound tokens.** A token flagged `bearer` is refused. The continuation and the management token never go to the browser.
- **Interaction finish** by redirect, with the hash from [RFC 9635 section 4.5.3](https://www.rfc-editor.org/rfc/rfc9635#section-4.5.3), or by push. The hash is checked in this process, and only for a grant this browser started.
- **Subject information**, including an `id_token` assertion checked against the issuer's JWKS. The audience may be the instance id or the application's identifier.
- **CAEP and RISC** on one Shared Signals poll stream, unless `signals` is false. The default is on, so an existing configuration keeps receiving events. The stream is authenticated with a GNAP access token and the same key proof. `signals: false` drops `ssf.read` and `ssf.manage`, does not contact a transmitter, and does not start the receiver. If those were the only rights, set `access` to a right the authorization server grants.

It is TypeScript and works from JavaScript, needs no web framework, and has no runtime dependency. It is built and tested against [iya-sts](https://rcbj.github.io/iya-sts/). How a GNAP application is registered there is [GNAP](https://rcbj.github.io/iya-sts/gnap.html) and [Configure a GNAP application](https://rcbj.github.io/iya-sts/configure-gnap.html).

MIT licensed. © 2026 Iya CyberSecurity Solutions, LLC.

## Install

```sh
npm install gnap-caep-risc-nodejs
```

## Where to read

- **[Server-side guide](guide.md):** the configuration, the key, the login route, and the callback.
- **[Handling CAEP and RISC events](signals.md):** what the receiver ends, and how it authenticates.
- **[Configuration and API reference](reference.md):** every setting and the API.
- **[TypeScript API](api/)** (TypeDoc), generated from the source.
- **[Setting up iya-sts](configure.md):** registering the key.
- **[Running the demo](demo.md):** a complete application in one container.
- **[Development and releases](development.md):** tests, CI, branches and versions.

## Quick look

```ts
import { GnapClient } from 'gnap-caep-risc-nodejs';

const gnap = GnapClient.fromFile('gnap.json');   // loads the key; does not discover

// GET /login
const started = await gnap.requestGrant();
// started.redirectUrl is where the browser goes.
// Keep started.pending.id with this browser. Do not keep the continuation token there.

// GET /callback
const done = await gnap.finishRedirect(query, { allowedIds });
console.log(done.grant.subject?.sub);
```

The configuration uses the same names as gnap-caep-js where they overlap, and adds the key:

```json
{
  "grantEndpoint": "https://idp.example/gnap",
  "transmitterIssuer": "https://idp.example",
  "idTokenIssuer": "https://idp.example",
  "application": "app",
  "display": { "name": "App", "uri": "https://app.example/" },
  "access": ["ssf.read", "ssf.manage"],
  "keyProof": "mtls",
  "privateKey": "file:keys/client.key",
  "certificate": "file:keys/client.crt",
  "finishUri": "https://app.example/callback",
  "finishMethod": "redirect"
}
```
