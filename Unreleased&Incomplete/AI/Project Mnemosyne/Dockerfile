# Build stage for frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/client
COPY client/package*.json ./
RUN npm ci
COPY client/ ./
RUN npm run build

# Build stage for backend
FROM node:20-alpine AS backend-builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY *.ts ./
COPY tsconfig.json ./
RUN npx tsc

# Production stage
FROM node:20-alpine
WORKDIR /app

# Create non-root user for security
RUN addgroup -g 1001 ctf && adduser -u 1001 -G ctf -s /bin/sh -D ctf

# Install production dependencies only
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy compiled backend
COPY --from=backend-builder /app/dist ./dist

# Copy built frontend
COPY --from=frontend-builder /app/client/dist ./client/dist

# Set ownership
RUN chown -R ctf:ctf /app

USER ctf

EXPOSE 3002

ENV NODE_ENV=production

CMD ["node", "dist/server.js"]
