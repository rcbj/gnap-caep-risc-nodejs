# syntax=docker/dockerfile:1
#
# The demo app's image. The library is compiled in the first stage; the second holds only what runs:
# the compiled library and the demo, whose server.ts Node runs as it is. There is no runtime dependency.
# The client key and the provider's TLS chain are NOT in the image: they are mounted at
# /app/demo/generated (docker-compose.yml), made on the host by generate-key and the setup script.
# 24.22.1: the 21 October 2026 security release, which fixes HTTP2Shell / Node2Shell (CVE-2026-111497).
FROM node:24.22.1-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
COPY packages/gnap-caep-risc-nodejs/package.json packages/gnap-caep-risc-nodejs/
COPY demo/package.json demo/
RUN npm ci --workspaces --include-workspace-root --ignore-scripts
COPY packages/gnap-caep-risc-nodejs/tsconfig.json packages/gnap-caep-risc-nodejs/
COPY packages/gnap-caep-risc-nodejs/src packages/gnap-caep-risc-nodejs/src
RUN npm run build -w packages/gnap-caep-risc-nodejs

FROM node:24.22.1-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/gnap-caep-risc-nodejs/package.json packages/gnap-caep-risc-nodejs/
COPY demo/package.json demo/
RUN npm ci --omit=dev --workspaces --include-workspace-root --ignore-scripts && npm cache clean --force
COPY --from=build /src/packages/gnap-caep-risc-nodejs/dist packages/gnap-caep-risc-nodejs/dist
COPY demo/server.ts demo/gnap.json demo/
COPY demo/public demo/public
USER node
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:3000/healthz >/dev/null || exit 1
CMD ["node", "demo/server.ts"]
