FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
COPY tsconfig.json ./
RUN npm ci

COPY src ./src
RUN npm run build

# Build dashboard
COPY dashboard/package*.json ./dashboard/
RUN cd dashboard && npm ci
COPY dashboard ./dashboard
RUN npm run build --prefix dashboard

# Production stage
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/dashboard/dist ./dashboard/dist
COPY waf-config*.json ./

RUN addgroup -g 1001 -S waf && adduser -S waf -u 1001
RUN chown -R waf:waf /app
USER waf

ENV NODE_ENV=production
ENV WAF_PORT=3000
ENV BACKEND_URL=http://localhost:8080

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/api/health', (r) => r.statusCode === 200 ? process.exit(0) : process.exit(1))"

CMD ["node", "dist/standalone/infinitex-server.js"]
