FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY challenge/package*.json ./

# Install dependencies
RUN npm install

# Copy source
COPY challenge/ .

# Build the application
RUN npm run build

# Production stage
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Create non-root user
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Copy built application
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

# Copy public folder (create if not exists)
RUN mkdir -p ./public
COPY --from=builder /app/public ./public

# Create entrypoint script that writes dynamic flag
RUN echo '#!/bin/sh' > /entrypoint.sh && \
    echo 'echo "${FLAG:-L3m0n{default_flag}}" > /flag.txt' >> /entrypoint.sh && \
    echo 'chmod 444 /flag.txt' >> /entrypoint.sh && \
    echo 'exec node server.js' >> /entrypoint.sh && \
    chmod +x /entrypoint.sh

# Set ownership
RUN chown -R nextjs:nodejs /app

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"
ENV FLAG="L3m0n{Ky0ug0ku_n0_K0t0tsu_B4NK41}"

# Run as root to write flag, then drop to nextjs
USER root

ENTRYPOINT ["/entrypoint.sh"]
