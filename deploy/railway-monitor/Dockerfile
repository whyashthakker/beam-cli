# Beam app monitoring for a Railway service: streams the service's HTTP request logs and app logs
# from Railway into `beam monitor`. Runs as its own Railway service, so the monitored app's code,
# image and start command never change. Build context: the beam-cli repository root.
FROM node:24-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:24-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates coreutils \
  && rm -rf /var/lib/apt/lists/* \
  && npm install -g @railway/cli@5.63.4 \
  && npm cache clean --force
WORKDIR /app
COPY package.json ./
# commander is the CLI's only runtime dependency (no transitive deps); copy the locked copy.
COPY --from=build /app/node_modules/commander ./node_modules/commander
COPY --from=build /app/dist ./dist
COPY Skills ./Skills

COPY deploy/railway-monitor/entrypoint.sh /usr/local/bin/beam-railway-monitor
RUN chmod 0755 /usr/local/bin/beam-railway-monitor \
  && useradd --create-home --uid 10001 beam
USER beam

ENTRYPOINT ["/usr/local/bin/beam-railway-monitor"]
