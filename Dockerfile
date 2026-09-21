# Accessible Multi-Factor Authentication (A-MFA)
# Production Container Image
FROM node:22-bookworm-slim

# Set working directory
WORKDIR /app

# Set production environment variables
ENV NODE_ENV=production \
    PORT=3000 \
    DB_PATH=/app/data/amfa.sqlite

# Copy dependency definitions
COPY package*.json ./

# Install production dependencies
RUN npm ci --omit=dev || npm install --omit=dev

# Copy application source code, static assets, and docs
COPY src ./src
COPY docs ./docs
COPY tests ./tests
COPY README.md ./

# Create data directory for SQLite persistence
RUN mkdir -p /app/data

# Expose standard application port
EXPOSE 3000

# Healthcheck using Node 22 built-in fetch
HEALTHCHECK --interval=20s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:3000/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

# Start the A-MFA server
CMD ["node", "src/server/index.js"]
