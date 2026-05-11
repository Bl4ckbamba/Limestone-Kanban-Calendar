FROM node:24-bookworm-slim

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV DATABASE_PATH=/data/limestone.sqlite

COPY package.json package-lock.json ./
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && npm ci --omit=dev \
  && npm cache clean --force \
  && apt-get purge -y --auto-remove python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

COPY server ./server
COPY dist ./dist
COPY bin ./bin

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 3000

CMD ["node", "server/index.js"]
