# BESTR3PS Full-Stack Unified Production Dockerfile
FROM node:24-alpine AS builder

WORKDIR /app

# Install build dependencies
COPY package*.json ./
RUN npm install

# Copy application source files
COPY . .

# Build React client bundle into ./dist
RUN npm run build

# --- Production Runner Stage ---
FROM node:24-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

# Install production dependencies only
COPY package*.json ./
RUN npm install --omit=dev

# Copy compiled assets from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/server.ts ./server.ts
COPY --from=builder /app/server ./server
COPY --from=builder /app/scripts ./scripts
COPY --from=builder /app/schema.sql ./schema.sql
COPY --from=builder /app/data_store ./data_store

# Ensure data_store and upload directories exist
RUN mkdir -p /app/data_store/uploads

# Expose production port
EXPOSE 3000

# Run full-stack Express server with tsx
CMD ["npx", "tsx", "server.ts"]
