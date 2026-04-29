import express from "express";
import path from "path";
import { createProxyMiddleware } from "http-proxy-middleware";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { getRedisClient } from './utils/redis.js';

const app = express();
const INTERNAL_PORT = parseInt(process.env.INTERNAL_PORT || "3000", 10);
const EXTERNAL_PORT = parseInt(process.env.PORT || "8080");
const LISTEN_HOST = process.env.HOST || '0.0.0.0';
const ARIA_INTERNAL = `http://localhost:${INTERNAL_PORT}`;

// Trust proxy for Railway (handles X-Forwarded-For header)
app.set('trust proxy', 1);

const SCAN_THRESHOLD = 10;

const normalizeIP = (ip: string | undefined): string => {
  if (!ip) return 'unknown';
  return ip.replace(/^::ffff:/, '');
};

const getRateLimitKey = (req: express.Request): string => {
  const cfIp = req.headers['cf-connecting-ip'];
  if (cfIp && typeof cfIp === 'string') return cfIp;
  return normalizeIP(req.ip);
};

app.use(helmet({ contentSecurityPolicy: false }));
app.disable("x-powered-by");

app.use(async (req, _res, next) => {
  const ip = getRateLimitKey(req);

  try {
    const redis = getRedisClient();
    if (redis) {
      const blocked = await redis.get(`membrane:blocked:${ip}`);
      if (blocked) return;
    }
  } catch (err) {
    console.warn('[membrane] Redis unavailable for block check, allowing request:', err instanceof Error ? err.message : err);
  }

  const suspiciousPatterns = [
    '/admin', '/internal', '/debug', '/test',
    '/config', '/.env', '/swagger', '/graphql',
    '/actuator', '/api/internal', '/wp-admin',
    '/phpmyadmin', '/manager', '/console', '/.git',
    '/backup', '/shell'
  ];

  const isSuspicious = suspiciousPatterns.some(p =>
    req.path === p || req.path.startsWith(p + '/')
  );

  if (isSuspicious) {
    try {
      const redis = getRedisClient();
      if (redis) {
        const count = await redis.incr(`membrane:scan:${ip}`);
        await redis.expire(`membrane:scan:${ip}`, 600);

        if (count >= SCAN_THRESHOLD) {
          await redis.set(`membrane:blocked:${ip}`, '1', 'EX', 86400);
          await redis.del(`membrane:scan:${ip}`);
          console.warn(`[membrane] IP ${ip} blocked after ${count} suspicious requests`);
        }
      }
    } catch (err) {
      console.warn('[membrane] Redis unavailable for scan tracking:', err instanceof Error ? err.message : err);
    }

    return;
  }

  next();
});

const membraneLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getRateLimitKey(req),
  handler: (_req, res) => {
    res.status(429).json({
      error: 'Too many requests',
      code: 'RATE_LIMITED'
    });
  },
});

app.use(membraneLimit);

app.use((req, res, next) => {
  const ALLOWED_METHODS = ['GET', 'POST', 'DELETE', 'OPTIONS'];
  if (!ALLOWED_METHODS.includes(req.method)) {
    return res.status(405).json({
      error: 'Method not allowed',
      code: 'METHOD_NOT_ALLOWED'
    });
  }
  next();
});

const ALLOWED_PATHS = [
  "/",
  "/app",
  "/privacy",
  "/health",
  "/v1/setup",
  "/v1/agents",
  "/v1/events",
  "/v1/auth",
  "/v1/api-keys",
  "/v1/webhooks",
];

app.use((req, _res, next) => {
  // "/" must be exact-matched — startsWith("/") would pass everything
  const allowed = ALLOWED_PATHS.some((p) =>
    p === "/" ? req.path === "/" : req.path.startsWith(p)
  );
  if (!allowed) {
    return;
  }
  next();
});

// Debug log for incoming requests
app.use((req, _res, next) => {
  console.log('[membrane] Received request:', req.method, req.url);
  next();
});

// Root route proxied to internal server (index.ts serves landing page from public/)

// Proxy all requests to internal Express
app.use(
  "/",
  createProxyMiddleware({
    target: ARIA_INTERNAL,
    changeOrigin: true,
    on: {
      error: (err, req, res) => {
        console.error('[membrane] Proxy error for:', req.url);
        try {
          (res as express.Response).status(502).json({
            error: "Bad Gateway",
            code: "MEMBRANE_PROXY_ERROR",
          });
        } catch {}
      },
    },
  })
);

// Wait for internal server with proper async delays
async function waitForInternalServer(): Promise<boolean> {
  console.log(`[membrane] Starting, will wait for internal API on port ${INTERNAL_PORT}`);
  for (let i = 1; i <= 30; i++) {
    try {
      const res = await fetch(`http://localhost:${INTERNAL_PORT}/health`);
      if (res.ok) {
        console.log(`[membrane] Internal API is ready!`);
        return true;
      }
    } catch (e) {
      // Continue retrying
    }
    console.log(`[membrane] Waiting for internal server... (${i}/30)`);
    await new Promise(r => setTimeout(r, 1000)); // KEY: Wait 1 second between retries
  }
  return false;
}

// Start membrane - try to connect, but START HTTP SERVER FIRST regardless
async function startMembrane() {
  // Start HTTP server immediately (it will handle errors gracefully)
  app.listen(EXTERNAL_PORT, LISTEN_HOST, () => {
    console.log(`[membrane] HTTP server started on port ${EXTERNAL_PORT}`);
  });
  
  // Then try to connect to internal
  const ready = await waitForInternalServer();
  
  if (!ready) {
    console.error("[membrane] Internal API not available - running in degraded mode");
  }
}

startMembrane();

export default app;
