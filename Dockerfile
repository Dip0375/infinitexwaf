FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY src ./src

# Build the application
RUN npm run build

# Production stage
FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production

# Copy built application
COPY --from=builder /app/dist ./dist
COPY waf-config.json ./

# Create non-root user
RUN addgroup -g 1001 -S waf && \
    adduser -S waf -u 1001

# Set ownership
RUN chown -R waf:waf /app

USER waf

# Environment variables
ENV NODE_ENV=production
ENV WAF_PORT=3000
ENV BACKEND_URL=http://localhost:8080

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/waf/health', (r) => r.statusCode === 200 ? process.exit(0) : process.exit(1))"

CMD ["node", "dist/standalone/server.js"]
