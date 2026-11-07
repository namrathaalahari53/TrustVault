import express, { Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import path from 'path';
import fs from 'fs';
import { db, DOCUMENTS_DIR, STORAGE_DIR } from './server/db';
import apiRouter from './server/routes';

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const isProduction = process.env.NODE_ENV === 'production';

// Security headers
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Health & Readiness Endpoints
app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'trustvault-core',
    version: '1.0.0',
  });
});

app.get('/ready', (_req: Request, res: Response) => {
  const storageReady = fs.existsSync(STORAGE_DIR) && fs.existsSync(DOCUMENTS_DIR);
  const dbReady = db.getUsers().length > 0;
  const auditValid = db.verifyAuditChain().is_valid;

  if (storageReady && dbReady && auditValid) {
    res.status(200).json({
      status: 'ready',
      storage_connected: true,
      database_ready: true,
      cryptographic_audit_chain_valid: true,
      timestamp: new Date().toISOString(),
    });
  } else {
    res.status(503).json({
      status: 'not_ready',
      storage_connected: storageReady,
      database_ready: dbReady,
      cryptographic_audit_chain_valid: auditValid,
      timestamp: new Date().toISOString(),
    });
  }
});

// Mount API routes
app.use('/api', apiRouter);

// Development with Vite or Production Static Serving
async function startServer() {
  if (!isProduction) {
    // Dynamic import vite in dev to mount middlewares
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    // Serve static frontend in production
    const distPath = path.resolve(process.cwd(), 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[TrustVault] Server running at http://0.0.0.0:${PORT} in ${isProduction ? 'production' : 'development'} mode`);
    console.log(`[TrustVault] Health check available at http://0.0.0.0:${PORT}/health`);
    console.log(`[TrustVault] Readiness check available at http://0.0.0.0:${PORT}/ready`);
  });
}

startServer().catch((err) => {
  console.error('[TrustVault] Fatal server bootstrap error:', err);
  process.exit(1);
});
