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

Open <http://localhost:3000>. The setup script's test user is `gnap-demo-user`.
