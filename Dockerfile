# ==============================================================================
# 🐳 SSH Microservice Dockerfile
# Multi-stage build for optimized production image
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build Stage
# ------------------------------------------------------------------------------
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    cairo-dev \
    jpeg-dev \
    pango-dev \
    musl-dev \
    giflib-dev \
    pixman-dev \
    pangomm-dev \
    libjpeg-turbo-dev \
    freetype-dev

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Copy source code
COPY src/ ./src/

# Build the application
RUN npm run build

# ------------------------------------------------------------------------------
# Stage 2: Production Stage
# ------------------------------------------------------------------------------
FROM node:18-alpine AS production

# Set labels
LABEL maintainer="SSH Microservice Team"
LABEL version="1.0.0"
LABEL description="SSH connection management and command execution microservice"

# Create app user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodeapp -u 1001

# Set working directory
WORKDIR /app

# Install runtime dependencies only
RUN apk add --no-cache \
    tini \
    dumb-init \
    curl \
    && rm -rf /var/cache/apk/*

# Copy built application from builder stage
COPY --from=builder --chown=nodeapp:nodejs /app/dist ./dist
COPY --from=builder --chown=nodeapp:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodeapp:nodejs /app/package*.json ./

# Create logs directory
RUN mkdir -p /app/logs && \
    chown -R nodeapp:nodejs /app/logs

# Create non-root user's home directory
RUN mkdir -p /home/nodeapp && \
    chown -R nodeapp:nodejs /home/nodeapp

# Set environment variables
ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0
ENV LOG_LEVEL=info

# Switch to non-root user
USER nodeapp

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Use tini as init process
ENTRYPOINT ["/sbin/tini", "--"]

# Start the application
CMD ["node", "dist/server.js"]

# ------------------------------------------------------------------------------
# Stage 3: Development Stage
# ------------------------------------------------------------------------------
FROM node:18-alpine AS development

# Set working directory
WORKDIR /app

# Install development dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    git \
    openssh-client \
    curl \
    vim \
    && rm -rf /var/cache/apk/*

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install all dependencies (including dev)
RUN npm ci && \
    npm cache clean --force

# Copy source code
COPY . .

# Create logs directory
RUN mkdir -p /app/logs

# Expose port and debugger port
EXPOSE 3000 9229

# Set environment variables
ENV NODE_ENV=development
ENV PORT=3000
ENV HOST=0.0.0.0
ENV LOG_LEVEL=debug

# Start with nodemon for development
CMD ["npm", "run", "dev"]

# ------------------------------------------------------------------------------
# Stage 4: Testing Stage
# ------------------------------------------------------------------------------
FROM development AS testing

# Set test environment
ENV NODE_ENV=test

# Run tests
RUN npm run test

# Keep container running for test debugging
CMD ["tail", "-f", "/dev/null"]