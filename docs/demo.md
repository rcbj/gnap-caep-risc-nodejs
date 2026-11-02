---
title: Running the demo
---

# Running the demo

The demo is a traditional web application. The server renders the pages. The browser holds a session cookie, not tokens. It is the same shape as the [saml2-sp-nodejs](https://github.com/rcbj/saml2-sp-nodejs) and [oidc-caep-risc-nodejs](https://github.com/rcbj/oidc-caep-risc-nodejs) demos: several accounts in one browser, an identity tab, a CAEP and RISC tab, a live event stream, verify, clear, sign-out of one account, and sign-out of all of them.

The heading and the account list show the access token's `uid` claim when the application configured one, and otherwise the user part of the `account` subject identifier. The identity tab's Username row is that same name. It also shows the GNAP subject: sub, email, name, issuer, provider session, the key proof, whether the token is bound, and the grant id. Shared Signals match the subject. The page does not show the token.

## With iya-sts

iya-sts listens on `https://localhost:8081`. From this repository:

```sh
npm install
npm run generate-key -- --config demo/gnap.json --cn localhost
ADMIN_API_CLIENT_SECRET=… GNAP_DEMO_USER_PASSWORD=… npm run configure-iya-sts
docker compose up --build
```

Open <http://localhost:3000> and sign in as `gnap-demo-user`. `PORT` defaults to 3000. A loopback finish URI follows `PORT`, and `configure-iya-sts` registers that URI.

`generate-key` writes `demo/generated/client.key` and `demo/generated/client.crt`. `configure-iya-sts` registers the public certificate as the GNAP key, proof `mtls`, and writes `demo/generated/idp-ca.pem`. That second file is the listener CA trust chain, and it is what `tlsCa` in `demo/gnap.json` names. The image build copies the chain file in, so the demo image trusts that iya-sts with no mount; run the setup script before `docker compose up --build`, and rebuild after running it against a different iya-sts. The key and certificate are never in the image: Compose mounts the directory into the container for them. When the container starts, it fetches the chain again and updates that file (unless `TLS_CA_REFRESH=0`), so a rebuilt listener certificate is picked up without a second setup run.

The container uses the host's network, so `https://localhost:8081` is the same address inside the container as in the browser. On Docker Desktop, turn on host networking.

To run it without Docker, after the setup script:

```sh
npm run build
npm start
```

`npm start` is `node demo/server.ts`. Node 22.18 or later runs that TypeScript as it is. The library has to be built first, because the demo imports the package and the package's entry is `dist/`.

The home page loads the key and does not discover. If the key files are missing it says so and does not offer the button. `/login` is what contacts the authorization server. If that fails, the page shows the error and the process keeps running.

## What you can do

- **Sign in with GNAP.** The button goes to `/login`, which starts a grant and redirects to `interact.redirect`. The provider comes back to `/callback` with `hash` and `interact_ref`. The server checks the hash against the pending id in the `gpending` cookie, continues the grant on the back channel, and answers 303 to `/u/<account>/`.
- **The five-second wait.** iya-sts's `gnap.continueWaitS` is 5 unless the realm sets another value. The library sleeps the remainder at the callback, not before the browser is redirected. The callback can take those few seconds.
- **Add another account.** That starts a new grant. If the same subject comes back, that account's session is refreshed instead of duplicated. iya-sts has to have `authn.multipleAccounts` on, which the setup script sets, or the provider ends the first session.
- **Two tabs, two people.** Each account has its own URL. Ending one does not change the other tab.
- **CAEP & RISC events.** The events tab follows this account only. The stream is the application's, polled with a key-bound GNAP access token proved by mutual TLS. The line on that tab says so. Change the person's password, sign them out at the provider, or disable the account, and the tab updates. The shipped `demo/gnap.json` leaves `signals` on. `signals: false` does not start the receiver: the tab says signals are off, and the process does not contact a transmitter.
- **Sign out of this account**, or of every account in this browser. That is local. The grant is kept so the stream can still be polled. Ending events are what close the provider side.

The pending cookie is `HttpOnly` and `SameSite=Lax`. It is not `Secure` while the finish URI is `http`, including `http://localhost:3000/callback`. It names at most three pending ids. The continuation token is not in it.

`POST /gnap/push` accepts a push finish. The demo's configuration uses redirect, because iya-sts will not dial an `http` push URI.
