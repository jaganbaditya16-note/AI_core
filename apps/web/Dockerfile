# syntax=docker/dockerfile:1

# ── AICore web ────────────────────────────────────────────────────────────────
# Build context: repository root (npm workspaces need the root lockfile).
#   docker build -f apps/web/Dockerfile .

# ── Build stage ───────────────────────────────────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /repo

# Install dependencies from the lockfile only, so this layer caches well.
COPY package.json package-lock.json ./
COPY apps/web/package.json ./apps/web/package.json
COPY packages/types/package.json ./packages/types/package.json
RUN npm ci

# Build the app (next build, output: standalone).
COPY packages/types ./packages/types
COPY apps/web ./apps/web
RUN npm run build --workspace @aicore/web

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM node:22-alpine AS runner

ENV NODE_ENV=production \
    PORT=3000 \
    HOSTNAME=0.0.0.0 \
    NEXT_TELEMETRY_DISABLED=1

WORKDIR /app

RUN addgroup --system --gid 10001 nodejs && \
    adduser --system --uid 10001 --ingroup nodejs nextjs

# The standalone server already contains the traced node_modules it needs.
COPY --from=builder --chown=nextjs:nodejs /repo/apps/web/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /repo/apps/web/.next/static ./apps/web/.next/static
COPY --from=builder --chown=nextjs:nodejs /repo/apps/web/public ./apps/web/public

USER nextjs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "apps/web/server.js"]
