# FRENET node image. UNTESTED: written without a Docker daemon available; build and run it once before relying on it.
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --no-audit --no-fund
COPY src ./src
COPY web ./web
COPY scripts/copy-web.mjs ./scripts/copy-web.mjs
RUN npm run build && npm prune --omit=dev

FROM node:22-slim
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
RUN useradd -m frenet && mkdir /data && chown frenet /data
USER frenet
VOLUME /data
# The dashboard/API listen on loopback inside the container only; nothing publishes them. Publish 4001 (tcp+udp) for peers.
EXPOSE 4001/tcp 4001/udp
ENTRYPOINT ["node", "dist/cli.js", "--data", "/data"]
CMD ["--relay-server", "--listen", "/ip4/0.0.0.0/tcp/4001", "--listen", "/ip4/0.0.0.0/udp/4001/quic-v1"]
