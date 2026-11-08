# syntax=docker/dockerfile:1
#
# The demo app's image. The library is compiled in the first stage; the second holds only what runs:
# the compiled library and the demo, whose server.ts Node runs as it is. There is no runtime dependency.
# The listener CA trust chain IS in the image: tlsCa's file, demo/generated/idp-ca.pem, which the
# install script (scripts/configure-iya-sts.ts) wrote before the build. The client key and its
# certificate are NOT: they are mounted at /app/demo/generated (docker-compose.yml). At start, the
# entrypoint refreshes the chain into the file tlsCa names, unless TLS_CA_REFRESH=0.
# 24.22.1: the 21 October 2026 security release, which fixes HTTP2Shell / Node2Shell (CVE-2026-111497).
FROM node:26.12.1-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
COPY packages/gnap-caep-risc-nodejs/package.json packages/gnap-caep-risc-nodejs/
COPY demo/package.json demo/
RUN npm ci --workspaces --include-workspace-root --ignore-scripts
COPY packages/gnap-caep-risc-nodejs/tsconfig.json packages/gnap-caep-risc-nodejs/
COPY packages/gnap-caep-risc-nodejs/src packages/gnap-caep-risc-nodejs/src
RUN npm run build -w packages/gnap-caep-risc-nodejs

# The setup script and the key generator, run from their TypeScript sources. scripts/live_iya_sts.py
# runs configure-iya-sts.ts and generate-key in this image, not on the host. `--target tools`.
FROM build AS tools
COPY VERSION ./
COPY scripts scripts
COPY demo/gnap.json demo/server.ts demo/uid-claim.ts demo/

# The unit suite: `docker build --target test .`. node:test against the stub authorization server and
# the stub transmitter, the setup script's plan, and the check that the manifests follow VERSION.
FROM tools AS test
# One test makes a throwaway certificate with the openssl command, which Alpine does not ship.
RUN apk add --no-cache openssl
COPY packages/gnap-caep-risc-nodejs/test packages/gnap-caep-risc-nodejs/test
RUN npm test && node scripts/version.mjs --check-manifests

FROM node:26.12.1-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/gnap-caep-risc-nodejs/package.json packages/gnap-caep-risc-nodejs/
COPY demo/package.json demo/
RUN npm ci --omit=dev --workspaces --include-workspace-root --ignore-scripts && npm cache clean --force
COPY --from=build /src/packages/gnap-caep-risc-nodejs/dist packages/gnap-caep-risc-nodejs/dist
# The demo, and with it tlsCa's file: demo/generated/idp-ca.pem, the iya-sts listener CA trust
# chain scripts/configure-iya-sts.ts saved. The image trusts that iya-sts with no bind mount and no
# fetch. Rebuild after running the install script against a different iya-sts.
# .dockerignore admits that one file from demo/generated (never the client key, its certificate or
# a password), and keeps out node_modules. A COPY of the demo DIRECTORY succeeds with or without
# the chain, so a fresh clone and CI still build; naming the file, or a glob that matches nothing,
# fails the build in both builders.
COPY demo demo
COPY scripts/trust-chain.mjs scripts/redirects.mjs scripts/
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
USER node
EXPOSE 3000
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD wget -qO- http://127.0.0.1:${PORT}/healthz >/dev/null || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["node", "demo/server.ts"]
