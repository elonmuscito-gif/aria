import express from "express";
import path from "path";
import { createProxyMiddleware } from "http-proxy-middleware";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

const app = express();
const INTERNAL_PORT = 3000;
const EXTERNAL_PORT = parseInt(process.env.PORT || "8080");
const ARIA_INTERNAL = `http://localhost:${INTERNAL_PORT}`;

// Trust proxy for Railway (handles X-Forwarded-For header)
app.set('trust proxy', 1);

const scanningIPs = new Map<string, number>();
const SCAN_THRESHOLD = 10;
const blockedIPs = new Set<string>();

app.use(helmet({ contentSecurityPolicy: false }));
app.disable("x-powered-by");

app.use((req, res, next) => {
  const ip = req.ip ?? "";
  if (blockedIPs.has(ip)) {
    return;
  }
  next();
});

app.use((req, _res, next) => {
  const ip = req.ip ?? "";
  const path = req.path;

  const suspiciousPatterns = [
    "/admin",
    "/internal",
    "/debug",
    "/test",
    "/config",
    "/env",
    "/.env",
    "/api/v1/internal",
    "/swagger",
    "/graphql",
    "/actuator",
  ];

  const isSuspicious = suspiciousPatterns.some((p) =>
    path.toLowerCase() === p || path.toLowerCase().startsWith(p + "/")
  );

  if (isSuspicious) {
    const count = (scanningIPs.get(ip) ?? 0) + 1;
    scanningIPs.set(ip, count);

    if (count >= SCAN_THRESHOLD) {
      blockedIPs.add(ip);
      console.warn(`[membrane] Blocked IP ${ip} after ${count} suspicious requests`);
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
  handler: (_req, _res) => {},
});

app.use(membraneLimit);

const ALLOWED_PATHS = [
  "/health",
  "/v1/setup",
  "/v1/agents",
  "/v1/events",
  "/v1/auth",
  "/v1/api-keys",
];

app.use((req, _res, next) => {
  const allowed = ALLOWED_PATHS.some((p) => req.path.startsWith(p));
  if (!allowed) {
    return;
  }
  next();
});

// Direct health endpoint for Railway (doesn't need internal API)
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'membrane', port: EXTERNAL_PORT });
});

// Also proxy /health to internal for full check
app.get('/api/health', async (req, res) => {
  try {
    const internalRes = await fetch(`http://localhost:${INTERNAL_PORT}/health`);
    const data = await internalRes.json() as { status: string; db?: string; uptime?: number };
    res.json({ status: data.status, db: data.db, uptime: data.uptime, membrane: 'proxied' });
  } catch {
    res.status(503).json({ status: 'error', internal: 'unreachable' });
  }
});

// Debug log for incoming requests
app.use(( req, _res, next) => {
  console.log('[membrane] Received request:', req.method, req.url);
  next();
});

// Health endpoints already added above

// Root route: serve landing page directly
app.get('/', (req, res) => {
  console.log('[membrane] Serving landing page');
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ARIA — Trust Infrastructure for Autonomous AI</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0a; color: #fff; min-height: 100vh; display: flex; align-items: center; justify-content: center; text-align: center; padding: 20px; }
    h1 { font-size: clamp(32px, 6vw, 56px); margin-bottom: 16px; background: linear-gradient(135deg, #fff, #00d4ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    p { font-size: 18px; color: #888; max-width: 500px; margin-bottom: 32px; }
    a { display: inline-block; padding: 14px 32px; background: #00d4ff; color: #0a0a0a; text-decoration: none; border-radius: 8px; font-weight: 600; }
    a:hover { background: #00b8e6; }
  </style>
</head>
<body>
  <div>
    <h1>Don't trust your AI agents. Verify them.</h1>
    <p>ARIA is the trust infrastructure for the agentic economy. Cryptographic identities, immutable audit trails, and zero-trust scope enforcement.</p>
    <a href="/health">Check Health</a>
  </div>
</body>
</html>`;
  res.setHeader('Content-Type', 'text/html');
res.send(html);
});

// Proxy all GET / to landing, otherwise to internal API
app.get('/', (req, res) => {
  console.log('[membrane] GET / - landing page');
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ARIA — Trust Infrastructure for Autonomous AI</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0a; color: #fff; min-height: 100vh; display: flex; align-items: center; justify-content: center; text-align: center; padding: 20px; }
    h1 { font-size: clamp(32px, 6vw, 56px); margin-bottom: 16px; background: linear-gradient(135deg, #fff, #00d4ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    p { font-size: 18px; color: #888; max-width: 500px; margin-bottom: 32px; }
    a { display: inline-block; padding: 14px 32px; background: #00d4ff; color: #0a0a0a; text-decoration: none; border-radius: 8px; font-weight: 600; }
  </style>
</head>
<body>
  <div>
    <h1>Don't trust your AI agents. Verify them.</h1>
    <p>ARIA - Trust Infrastructure for Autonomous AI</p>
    <a href="/health">Health Check</a>
  </div>
</body>
</html>`;
  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

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

setInterval(() => {
  scanningIPs.clear();
}, 10 * 60 * 1000);

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
  app.listen(EXTERNAL_PORT, () => {
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