import express from "express";
import { admissionRouter } from "./routes/admission";
import { logger } from "./middleware/logger";

const app = express();
const PORT = parseInt(process.env.PORT ?? "8080", 10);

// Middleware
app.use(express.json({ limit: "1mb" }));

// Request logging
app.use((req, _res, next) => {
  logger.debug(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.get("user-agent"),
  });
  next();
});

// Routes
app.use("/admission", admissionRouter);

// Global health check
app.get("/healthz", (_req, res) => {
  res.json({ status: "ok", service: "policy-api", timestamp: new Date().toISOString() });
});

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

// Error handler
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error("Unhandled error", { error: err.message, stack: err.stack });
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
  logger.info(`policy-api listening`, { port: PORT, env: process.env.NODE_ENV ?? "development" });
});

export default app;
