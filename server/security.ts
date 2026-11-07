import crypto from 'crypto';
import path from 'path';
import { Request, Response, NextFunction } from 'express';
import { db, UserRecord, DocumentRecord } from './db';

const JWT_SECRET = process.env.JWT_SECRET || 'trustvault-enterprise-sec-token-2026-strict-key-928174';
const TOKEN_EXPIRY_MS = 1000 * 60 * 60 * 2; // 2 hours short-lived token

export interface AuthContext {
  userId: string;
  email: string;
  role: 'ADMIN' | 'OWNER' | 'VIEWER';
  user: UserRecord;
}

// Augment Express Request
declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
      requestId?: string;
    }
  }
}

// In-memory rate limiting for brute-force protection
interface RateLimitRecord {
  attempts: number;
  blockedUntil: number;
}
const loginRateLimitMap = new Map<string, RateLimitRecord>();

export function checkLoginRateLimit(ipOrEmail: string): { allowed: boolean; waitSeconds?: number } {
  const key = ipOrEmail.toLowerCase();
  const record = loginRateLimitMap.get(key);
  const now = Date.now();

  if (record && record.blockedUntil > now) {
    const waitSeconds = Math.ceil((record.blockedUntil - now) / 1000);
    return { allowed: false, waitSeconds };
  }

  return { allowed: true };
}

export function clearLoginRateLimit(ipOrEmail?: string): void {
  if (ipOrEmail) {
    loginRateLimitMap.delete(ipOrEmail.toLowerCase());
  } else {
    loginRateLimitMap.clear();
  }
}

export function recordLoginAttempt(ipOrEmail: string, success: boolean): void {
  const key = ipOrEmail.toLowerCase();
  const now = Date.now();
  const record = loginRateLimitMap.get(key) || { attempts: 0, blockedUntil: 0 };

  if (success) {
    loginRateLimitMap.delete(key);
    return;
  }

  record.attempts += 1;
  // If 10 failed attempts within window, block for 5 minutes
  if (record.attempts >= 10) {
    record.blockedUntil = now + 5 * 60 * 1000;
  }
  loginRateLimitMap.set(key, record);
}

// Generate signed bearer token
export function generateToken(user: UserRecord): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      sub: user.id,
      email: user.email,
      role: user.role,
      exp: Date.now() + TOKEN_EXPIRY_MS,
      iat: Date.now(),
      jti: crypto.randomUUID(),
    })
  ).toString('base64url');

  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${header}.${payload}`)
    .digest('base64url');

  return `${header}.${payload}.${signature}`;
}

export function verifyToken(token: string): { sub: string; email: string; role: 'ADMIN' | 'OWNER' | 'VIEWER' } | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, payload, signature] = parts;

    const expectedSig = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(`${header}.${payload}`)
      .digest('base64url');

    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
      return null;
    }

    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (Date.now() > decoded.exp) {
      return null; // Expired
    }

    return decoded;
  } catch {
    return null;
  }
}

// Middleware: Authenticate User
export function requireAuthenticatedUser(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  const cookieToken = req.cookies?.['trustvault_token'];
  let token: string | undefined;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else if (cookieToken) {
    token = cookieToken;
  }

  if (!token) {
    res.status(401).json({
      error: 'AUTHENTICATION_REQUIRED',
      message: 'Authentication token missing or invalid.',
    });
    return;
  }

  const payload = verifyToken(token);
  if (!payload) {
    res.status(401).json({
      error: 'INVALID_OR_EXPIRED_TOKEN',
      message: 'Session has expired or token is invalid. Please log in again.',
    });
    return;
  }

  const user = db.findUserById(payload.sub);
  if (!user || !user.is_active) {
    // Record unauthorized attempt for inactive or non-existent user
    db.appendAuditEvent({
      actor_user_id: payload.sub,
      actor_email: payload.email,
      action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      document_id: null,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: user ? 'ACCOUNT_INACTIVE' : 'USER_NOT_FOUND',
      request_id: req.requestId || crypto.randomUUID(),
    });

    res.status(401).json({
      error: 'ACCOUNT_DEACTIVATED',
      message: 'Account is deactivated or suspended. Access denied.',
    });
    return;
  }

  req.auth = {
    userId: user.id,
    email: user.email,
    role: user.role,
    user,
  };

  next();
}

// Middleware: Require Admin Role
export function requireAdminRole(req: Request, res: Response, next: NextFunction): void {
  if (!req.auth || req.auth.role !== 'ADMIN') {
    db.appendAuditEvent({
      actor_user_id: req.auth?.userId || null,
      actor_email: req.auth?.email || 'unknown',
      action: 'ADMIN_PRIVILEGE_VIOLATION',
      document_id: null,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: 'INSUFFICIENT_ADMIN_PRIVILEGES',
      request_id: req.requestId || crypto.randomUUID(),
    });

    res.status(403).json({
      error: 'FORBIDDEN_ROLE',
      message: 'Administrative privileges required to access this resource.',
    });
    return;
  }
  next();
}

// Document Read Authorization Checker
export function checkDocumentReadAccess(
  user: UserRecord,
  doc: DocumentRecord
): { allowed: boolean; reason?: string } {
  // 1. Owner always has read access
  if (doc.owner_id === user.id) {
    return { allowed: true };
  }

  // 2. Explicit active document permission (READ or EDIT)
  const perm = db.findActivePermission(doc.id, user.id);
  if (perm && (perm.permission_level === 'READ' || perm.permission_level === 'EDIT')) {
    return { allowed: true };
  }

  // 3. Admin does not get automatic un-audited document content access unless granted or owner
  return { allowed: false, reason: 'NO_ACTIVE_READ_PERMISSION' };
}

// Document Edit Authorization Checker
export function checkDocumentEditAccess(
  user: UserRecord,
  doc: DocumentRecord
): { allowed: boolean; reason?: string } {
  // 1. Owner always has edit access
  if (doc.owner_id === user.id) {
    return { allowed: true };
  }

  // 2. Explicit active permission must be EDIT
  const perm = db.findActivePermission(doc.id, user.id);
  if (perm && perm.permission_level === 'EDIT') {
    return { allowed: true };
  }

  return { allowed: false, reason: 'NO_ACTIVE_EDIT_PERMISSION' };
}

// Document Owner Authorization Checker
export function checkDocumentOwnership(
  user: UserRecord,
  doc: DocumentRecord
): { allowed: boolean; reason?: string } {
  if (doc.owner_id === user.id) {
    return { allowed: true };
  }
  return { allowed: false, reason: 'NOT_DOCUMENT_OWNER' };
}

// Safe Filename Sanitizer (Path Traversal Protection)
export function sanitizeFilename(rawFilename: string): string {
  // Strip null bytes, paths, and normalize
  const base = path.basename(rawFilename).replace(/\0/g, '');
  // Disallow hidden files or dangerous characters
  return base.replace(/[^a-zA-Z0-9._\- ]/g, '_');
}

// Magic Byte / Signature Validator
export function validateFileMagicBytes(buffer: Buffer, declaredExt: string): { valid: boolean; reason?: string } {
  const ext = declaredExt.toLowerCase();

  // Max 50MB file size limit
  if (buffer.length > 50 * 1024 * 1024) {
    return { valid: false, reason: 'File size exceeds maximum permitted limit (50MB).' };
  }

  if (buffer.length === 0) {
    return { valid: false, reason: 'File is empty.' };
  }

  // PDF: %PDF- (25 50 44 46)
  if (ext === '.pdf') {
    if (buffer.length < 4 || buffer.toString('utf8', 0, 4) !== '%PDF') {
      return { valid: false, reason: 'Invalid file signature: Content does not match genuine PDF magic header.' };
    }
    return { valid: true };
  }

  // PNG: 89 50 4E 47
  if (ext === '.png') {
    if (buffer.length < 8 || buffer[0] !== 0x89 || buffer[1] !== 0x50 || buffer[2] !== 0x4e || buffer[3] !== 0x47) {
      return { valid: false, reason: 'Invalid file signature: Content does not match genuine PNG magic header.' };
    }
    return { valid: true };
  }

  // JPEG: FF D8 FF
  if (ext === '.jpg' || ext === '.jpeg') {
    if (buffer.length < 3 || buffer[0] !== 0xff || buffer[1] !== 0xd8 || buffer[2] !== 0xff) {
      return { valid: false, reason: 'Invalid file signature: Content does not match genuine JPEG magic header.' };
    }
    return { valid: true };
  }

  // DOCX / XLSX: PK\x03\x04 (ZIP Archive)
  if (ext === '.docx' || ext === '.xlsx') {
    if (buffer.length < 4 || buffer[0] !== 0x50 || buffer[1] !== 0x4b || buffer[2] !== 0x03 || buffer[3] !== 0x04) {
      return { valid: false, reason: 'Invalid file signature: Content does not match genuine Office OpenXML container.' };
    }
    return { valid: true };
  }

  // Plain Text / CSV
  if (ext === '.txt' || ext === '.csv') {
    // Check for null bytes (binary files pretending to be text)
    const sampleLength = Math.min(buffer.length, 1024);
    for (let i = 0; i < sampleLength; i++) {
      if (buffer[i] === 0x00) {
        return { valid: false, reason: 'Executable or binary content detected in declared plain text / CSV file.' };
      }
    }
    return { valid: true };
  }

  // Supported extensions whitelist
  const allowed = ['.pdf', '.doc', '.docx', '.txt', '.csv', '.xlsx', '.png', '.jpg', '.jpeg'];
  if (!allowed.includes(ext)) {
    return { valid: false, reason: `File type '${ext}' is not permitted by TrustVault security policy.` };
  }

  return { valid: true };
}
