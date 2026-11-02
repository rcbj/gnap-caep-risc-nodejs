# gnap-caep-risc-nodejs

A **server-side GNAP client** for traditional Node.js web applications, written in TypeScript and usable from JavaScript, and a traditional web demo built on it. The key is registered and proved by mutual TLS, an HTTP message signature, or a detached JWS. Tokens are key-bound. The library also receives CAEP and RISC events on one Shared Signals poll stream. It has no runtime dependency.

The configuration uses the same names as [`gnap-caep-js`](https://github.com/rcbj/gnap-caep-js) where they overlap. That project is a browser application and identifies itself with a `class_id`. This one is a server, and the key is the credential.

It is built and tested against [iya-sts](https://rcbj.github.io/iya-sts/). How that service registers a GNAP application is [its GNAP page](https://rcbj.github.io/iya-sts/gnap.html) and [Configure a GNAP application](https://rcbj.github.io/iya-sts/configure-gnap.html).

**Documentation:** <https://rcbj.github.io/gnap-caep-risc-nodejs/>

| Path | |
|---|---|
| [`packages/gnap-caep-risc-nodejs`](packages/gnap-caep-risc-nodejs) | The library, published to npm as [`gnap-caep-risc-nodejs`](https://www.npmjs.com/package/gnap-caep-risc-nodejs). |
| [`demo`](demo) | A traditional server-rendered web application, run in one container. |
| [`scripts/configure-iya-sts.ts`](scripts/configure-iya-sts.ts) | Registers the GNAP client on a running iya-sts and creates a test user. |

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).

## Install

```sh
npm install gnap-caep-risc-nodejs
```

See the [package README](packages/gnap-caep-risc-nodejs/README.md) for the reference and the [server-side guide](packages/gnap-caep-risc-nodejs/docs/guide.md) for a walkthrough.

## Run the demo

With [iya-sts](https://rcbj.github.io/iya-sts/) on `https://localhost:8081`:

```sh
npm install
npm run generate-key -- --config demo/gnap.json --cn localhost
ADMIN_API_CLIENT_SECRET=… npm run configure-iya-sts
docker compose up --build
```

Open <http://localhost:3000>. The setup script's test user is `gnap-demo-user`. Unless `GNAP_DEMO_USER_PASSWORD` sets its password, iya-sts generates one, and the install script writes it to `demo/generated/gnap-demo-user.password` (created mode 0600) and prints only that path, never the password.

`GET /live-status` is JSON for the sign-in in this browser and the Shared Signals events the demo has accepted: `signedIn`, `subject`, `receiver`, and events of `type` and `jti`. It does not include tokens.

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/gnap.json` names the iya-sts TLS listener CA trust chain the library trusts. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be `file:<path>`, `env:<NAME>`, or the PEM itself. The library trusts every certificate in it, in addition to Node's own store.

`scripts/configure-iya-sts.ts`, the install script, writes that file. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`; the client key, its certificate and the test user's password stay out of the image. A build with no chain file yet (a fresh clone, CI's `--target test`) still succeeds; the image then has no `tlsCa` file.

The mechanism is `COPY demo demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, BuildKit fails on the missing path and the classic builder fails with "no source files were specified". A directory COPY of `demo/` (which always exists) succeeds in both.

The container entrypoint also refreshes the file from the provider at start, because a development iya-sts makes a new CA when it restarts. A failed refresh keeps the file from the build. `TLS_CA_REFRESH=0` turns the refresh off. `node scripts/trust-chain.mjs --config demo/gnap.json` refreshes it by hand. Compose still mounts `demo/generated` (for the client key and certificate), which hides the image's copy behind the host's file.

## Tests

```sh
docker build --target test .
```

That target runs the unit suite in the Node image. It uses a stub authorization server and a stub transmitter.

`python3 scripts/live_iya_sts.py` is the live half. It starts a fresh iya-sts from its `main` branch in memory mode when `IYA_STS_URL` is unset (`IYA_STS_IMAGE` names an iya-sts image to start instead of building one). It copies this checkout to a scratch build context, generates the demo's key and runs the install script `scripts/configure-iya-sts.ts` in this repository's `tools` image, which writes the `tlsCa` chain. Then it builds the demo image, checks the image carries the chain and nothing else from `demo/generated`, starts it with only the client key and certificate mounted and `TLS_CA_REFRESH=0`, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. `LIVE_STS_PORT` (default 18547) and `LIVE_DEMO_PORT` (default 18647) choose the ports. It never binds port 3000, 8081, or 18481 to 18495, and it runs no Node on the host. The nightly workflow runs the unit suite and this script at 06:00 UTC.
