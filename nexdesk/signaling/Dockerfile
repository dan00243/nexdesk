FROM node:20-alpine AS builder
WORKDIR /build
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

FROM node:20-alpine
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=builder /build/node_modules ./node_modules
COPY --chown=app:app . .
USER app
HEALTHCHECK --interval=15s --timeout=5s --retries=3 CMD wget -qO- http://localhost:7879/health || exit 1
EXPOSE 7879
CMD ["node", "server.js"]
