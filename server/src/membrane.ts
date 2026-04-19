import express from "express";
import { createProxyMiddleware } from "http-proxy-middleware";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

const app = express();
const INTERNAL_PORT = parseInt(process.env.INTERNAL_PORT ?? "3001");
const MEMBRANE_PORT = parseInt(process.env.PORT ?? "8080");
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

app.use(
  "/",
  createProxyMiddleware({
    target: ARIA_INTERNAL,
    changeOrigin: true,
    on: {
      error: (_err, _req, res) => {
        (res as express.Response).status(503).json({
          error: "Service unavailable",
          code: "MEMBRANE_ERROR",
        });
      },
    },
  })
);

setInterval(() => {
  scanningIPs.clear();
}, 10 * 60 * 1000);

async function waitForServer(url: string, retries = 10): Promise<void> {
  for (let i = 0; i < retries; i++) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {}
    console.log(`[membrane] Waiting for internal server... (${i + 1}/${retries})`);
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error("[membrane] Internal server not available");
}

waitForServer(`http://localhost:${INTERNAL_PORT}/health`)
  .then(() => {
    console.log("[membrane] Internal server ready");
    app.listen(MEMBRANE_PORT, () => {
      console.log(`[membrane] ARIA Membrane running on port ${MEMBRANE_PORT}`);
    });
  })
  .catch((err) => {
    console.error(err.message);
    process.exit(1);
  });

export default app;