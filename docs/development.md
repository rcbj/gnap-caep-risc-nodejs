---
title: Development and releases
---

# Development and releases

## Tests

```sh
npm install
npm test
npm run build
```

`npm test` runs `node:test` on the TypeScript sources: the GNAP client against a stub authorization server (HTTP message signatures, detached JWS, and mutual TLS, each verified by the stub's own reconstruction of the signed input), the interaction hash, bearer and audience refusals, the Shared Signals receiver against a stub transmitter, the setup script's plan, and the version numbering. Nothing is fetched from a network except `npm view` when a version command asks what is already published, and the tests set `NPM_PUBLISHED_VERSIONS` so they do not.

`npm run build` compiles `packages/gnap-caep-risc-nodejs/src` to `dist/` with TypeScript 7, strict. The tests are not part of that compilation. Node runs them by stripping the types.

Node.js 22.18 or later is required to run the TypeScript sources. The published package is JavaScript and runs on Node 22.12 or later (`require()` of an ES module). The library has no runtime dependency.

## Continuous integration

| Workflow | Runs on | Does |
|---|---|---|
| `tests.yml` | every push and pull request | `npm test`, the build, the manifests check, then the demo image: the sign-in page and its security headers |
| `npm-publish.yml` | pushes to `main` and `develop` that change the package | tests, stamps the version, packs, and publishes to npm with provenance |
| `pages.yml` | pushes to `main` that change the docs or the source | builds this site and the TypeDoc reference |

The demo job generates a throwaway key and does not call `/login`. That route discovers the authorization server, and the job does not run one. The home page has to render from the key files alone.

Node 24.22.1 is the image and one of the two CI versions (the 21 October 2026 security release). 22.18.0 is the other.

## Branches

- **`develop`** is where work comes together: branch from it and merge back into it.
- **`main`** is what is released.

## Versions and releases

`M.N` is in the `VERSION` file; the patch number is worked out at build time from what is on npm (`scripts/version.mjs`). `main` publishes `M.N.P` under `latest`; `develop` publishes `M.N.P-next.R` under `next`. After bumping `VERSION`, run `npm run version:sync`.

The first publish needs the repository secret `NPM_TOKEN`. After the package exists, trusted publishing (this repository, workflow `npm-publish.yml`, environment `npm`) replaces it.

## Pages

GitHub Pages builds from the workflow. Before the first deployment, Pages has to exist as a workflow build:

```sh
gh api -X POST repos/rcbj/gnap-caep-risc-nodejs/pages -f build_type=workflow
```
