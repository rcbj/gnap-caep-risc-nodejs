# gnap-caep-risc-nodejs

A server-side GNAP client (RFC 9635) for a traditional Node.js application, and a CAEP and RISC receiver on one Shared Signals poll stream. It is TypeScript, usable from JavaScript, and has no runtime dependency. The key is registered and proved by mutual TLS, an HTTP message signature, or a detached JWS. Tokens are key-bound.

The browser library is [gnap-caep-js](https://github.com/rcbj/gnap-caep-js) (published as `gnap-caep-client`). That one sends a `class_id` because a page cannot hold the private key. This one holds the key.

Documentation: <https://rcbj.github.io/gnap-caep-risc-nodejs/>. The license is the MIT License in `LICENSE`. The Business Source License used by iya-sts does not apply here.

Node.js 22.18 or later. The package engines field says `>=22.18.0`. Continuous integration runs the suite on 22.18.0 and 24.22.1.

## Layout

| Path | What it is |
|---|---|
| `packages/gnap-caep-risc-nodejs` | The library published to npm as `gnap-caep-risc-nodejs`. Source is `src/` (`client.ts`, `config.ts`, `keys.ts`, `httpsig.ts`, `jwsd.ts`, `x509.ts`, `ssf/`). Tests are `test/`. `npm run build` writes `dist/`. |
| `demo` | The server-rendered demo. `demo/server.ts` and `demo/public/`. Config is `demo/gnap.json`. |
| `scripts` | `configure-iya-sts.ts` registers the client on iya-sts. `live_iya_sts.py` signs the demo in to a fresh iya-sts and checks two Shared Signals events. `redirects.mjs` rewrites a loopback URL onto `PORT`. `version.mjs` stamps the published version. |
| `docs` | The GitHub Pages site. |
| `tools/apidocs` | TypeDoc. It is outside the npm workspace. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

The root `package.json` is a private workspace. Committed manifests stay at `M.N.0` from the root `VERSION` file.

## Usage

```sh
npm install gnap-caep-risc-nodejs
```

```ts
import { GnapClient } from 'gnap-caep-risc-nodejs';

const gnap = GnapClient.fromFile('gnap.json');
const started = await gnap.requestGrant();
const done = await gnap.finishRedirect(query, { allowedIds });
```

The package README and `packages/gnap-caep-risc-nodejs/docs/guide.md` are the reference. A bearer token is refused.

## Tests

```sh
docker build --target test .
```

That stage runs `npm test` and the manifest check in the Node image. Do not run Node or npm on the host. The in-image commands are:

```sh
npm ci
npm test
npm run build
npm run version:check
```

`npm test` runs `node:test` on the TypeScript sources in `packages/gnap-caep-risc-nodejs/test` and on `scripts/*.test.ts`. The library tests use a stub authorization server and a stub transmitter. `version:check` fails unless every manifest is `M.N.0`.

The stub tests do not start iya-sts. `python3 scripts/live_iya_sts.py` does, unless `IYA_STS_URL` names one that is already running; `IYA_STS_IMAGE` starts a fresh container from that image instead of cloning and building `main`. It generates the key and runs `scripts/configure-iya-sts.ts` in the `tools` stage image, runs the demo image on `LIVE_DEMO_PORT` (default 18600) with host networking, signs in through `/authn-api`, emits credential-change and then session-revoked, and checks both on `GET /live-status`. iya-sts is published on `127.0.0.1:LIVE_STS_PORT` (default 18500). Use a fresh iya-sts for every run: a second registration of the same application keeps the old key. It never binds port 3000 or 8081. `.github/workflows/nightly.yml` runs the unit suite and this script at 06:00 UTC (`0 6 * * *`) and on demand.

`.github/workflows/tests.yml` also builds the demo image and checks what it serves. That job publishes host port 3000. Do not run it while a demo is already bound there. The in-process commands above do not need the container.

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
npm install
npm run generate-key -- --config demo/gnap.json --cn localhost
ADMIN_API_CLIENT_SECRET=… npm run configure-iya-sts
docker compose up --build
```

Open <http://localhost:3000>. The setup script's test user is `gnap-demo-user`.

A loopback finish URI follows `PORT` in the running server and in `scripts/configure-iya-sts.ts`. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. The running container's `PORT` wins over the shell's when the script registers the application. `ssf.pollIntervalMs` of 3000 in `demo/gnap.json` is a millisecond pause, not a port. `GET /live-status` reports the sign-in in this browser, the receiver state, and the type and `jti` of each accepted event. It does not include tokens.

## Releases

`main` publishes `M.N.P` as npm `latest`. `develop` publishes `M.N.P-next.R` as `next`. The patch is chosen at publish time by `scripts/version.mjs` from the versions already on npm. After bumping `VERSION`, run `npm run version:sync`.

`.github/workflows/npm-publish.yml` runs only when the push changes the package directory, `VERSION`, `package-lock.json`, `scripts/version.mjs`, or that workflow. A change that is only this file, the demo, or the docs does not publish. A pull request packs and publishes nothing.

## Changes

Branch from `develop`. Open a pull request into `develop` and merge it there. The default branch is `main`, so a closing keyword on that pull request does not close the issue. Close the issue in a comment that names the `develop` commit. Then merge `develop` into `main`, and fast-forward `develop` to that same commit so both branches name one hash.
