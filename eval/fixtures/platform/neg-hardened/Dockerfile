FROM node:22.11.0-alpine3.20 AS build
RUN apk add --no-cache curl
FROM node:22.11.0-alpine3.20 AS runner
USER node
COPY --chown=node . /app
