import express, { Request, Response } from 'express';
import multer from 'multer';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import {
  db,
  DOCUMENTS_DIR,
  computeSha256,
  hashPassword,
  verifyPassword,
} from './db';
import {
  generateToken,
  requireAuthenticatedUser,
  requireAdminRole,
  checkDocumentReadAccess,
  checkDocumentEditAccess,
  checkDocumentOwnership,
  sanitizeFilename,
  validateFileMagicBytes,
  checkLoginRateLimit,
  recordLoginAttempt,
} from './security';
import { runSecurityTestSuite } from './tests_runner';

const router = express.Router();

// Configure Multer for memory buffer upload to inspect magic bytes before writing to disk
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB
  },
});

// Middleware to assign unique request IDs for audit correlation
router.use((req: Request, _res: Response, next) => {
  req.requestId = `req_${crypto.randomUUID().slice(0, 10)}`;
  next();
});

// ==========================================
// AUTHENTICATION & REGISTRATION ENDPOINTS
// ==========================================

router.post('/auth/register', (req: Request, res: Response): void => {
  const { email, password, full_name, department, role } = req.body;
  const ip = req.ip || '127.0.0.1';

  if (!email || !password || !full_name) {
    res.status(400).json({
      error: 'MISSING_FIELDS',
      message: 'Full name, corporate email address, and secure password are required.',
    });
    return;
  }

  const cleanEmail = email.trim().toLowerCase();
  if (!cleanEmail.includes('@') || !cleanEmail.includes('.')) {
    res.status(400).json({
      error: 'INVALID_EMAIL',
      message: 'Please provide a valid corporate email address.',
    });
    return;
  }

  if (password.length < 10) {
    res.status(400).json({
      error: 'WEAK_PASSWORD',
      message: 'Password must be at least 10 characters long and contain letters, numbers, and symbols.',
    });
    return;
  }

  // Check email uniqueness
  const existing = db.findUserByEmail(cleanEmail);
  if (existing) {
    db.appendAuditEvent({
      actor_user_id: null,
      actor_email: cleanEmail,
      action: 'REGISTRATION_FAILED',
      document_id: null,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: 'EMAIL_ALREADY_REGISTERED',
      request_id: req.requestId!,
      metadata: { ip },
    });

    res.status(409).json({
      error: 'EMAIL_EXISTS',
      message: 'An account with this email address already exists. Please sign in or use another email.',
    });
    return;
  }

  // Role validation: Public self-registration can create OWNER or VIEWER (never ADMIN)
  const safeRole: 'OWNER' | 'VIEWER' = role === 'VIEWER' ? 'VIEWER' : 'OWNER';

  const passwordHash = hashPassword(password);
  const newUser = db.createUser({
    email: cleanEmail,
    full_name: full_name.trim(),
    department: (department || 'General').trim(),
    role: safeRole,
    is_active: true,
    must_change_password: false,
    password_hash: passwordHash,
    last_login_at: new Date().toISOString(),
  });

  const token = generateToken(newUser);

  db.appendAuditEvent({
    actor_user_id: newUser.id,
    actor_email: newUser.email,
    action: 'USER_REGISTERED',
    document_id: null,
    target_user_id: newUser.id,
    outcome: 'SUCCESS',
    reason_code: 'SELF_SERVICE_REGISTRATION',
    request_id: req.requestId!,
    metadata: {
      role: newUser.role,
      department: newUser.department,
      ip,
    },
  });

  res.cookie('trustvault_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 2 * 60 * 60 * 1000,
  });

  res.status(201).json({
    token,
    user: {
      id: newUser.id,
      email: newUser.email,
      role: newUser.role,
      full_name: newUser.full_name,
      department: newUser.department,
      must_change_password: newUser.must_change_password,
      created_at: newUser.created_at,
    },
  });
});

router.post('/auth/login', (req: Request, res: Response): void => {
  const { email, password } = req.body;
  const ip = req.ip || '127.0.0.1';

  if (!email || !password) {
    res.status(400).json({ error: 'MISSING_CREDENTIALS', message: 'Email and password are required.' });
    return;
  }

  const cleanEmail = email.trim().toLowerCase();

  // Check rate limit
  const rateLimit = checkLoginRateLimit(`${cleanEmail}_${ip}`);
  if (!rateLimit.allowed) {
    db.appendAuditEvent({
      actor_user_id: null,
      actor_email: cleanEmail,
      action: 'LOGIN_FAILURE',
      document_id: null,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: 'RATE_LIMIT_EXCEEDED',
      request_id: req.requestId!,
      metadata: { waitSeconds: rateLimit.waitSeconds, ip },
    });

    res.status(429).json({
      error: 'RATE_LIMIT_EXCEEDED',
      message: `Too many failed login attempts. Account temporarily locked for ${rateLimit.waitSeconds} seconds.`,
    });
    return;
  }

  const user = db.findUserByEmail(cleanEmail);

  if (!user || !verifyPassword(password, user.password_hash)) {
    recordLoginAttempt(`${cleanEmail}_${ip}`, false);

    db.appendAuditEvent({
      actor_user_id: user ? user.id : null,
      actor_email: cleanEmail,
      action: 'LOGIN_FAILURE',
      document_id: null,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: !user ? 'USER_NOT_FOUND' : 'INVALID_PASSWORD',
      request_id: req.requestId!,
      metadata: { ip },
    });

    res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' });
    return;
  }

  // Account inactive check
  if (!user.is_active) {
    db.appendAuditEvent({
      actor_user_id: user.id,
      actor_email: user.email,
      action: 'LOGIN_FAILURE',
      document_id: null,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: 'ACCOUNT_DEACTIVATED',
      request_id: req.requestId!,
      metadata: { ip },
    });

    res.status(403).json({ error: 'ACCOUNT_INACTIVE', message: 'Account is deactivated. Contact security admin.' });
    return;
  }

  // Login success
  recordLoginAttempt(`${cleanEmail}_${ip}`, true);
  db.updateUser(user.id, { last_login_at: new Date().toISOString() });

  const token = generateToken(user);

  db.appendAuditEvent({
    actor_user_id: user.id,
    actor_email: user.email,
    action: 'LOGIN_SUCCESS',
    document_id: null,
    target_user_id: null,
    outcome: 'SUCCESS',
    reason_code: 'AUTHENTICATION_SUCCESSFUL',
    request_id: req.requestId!,
    metadata: { role: user.role, ip },
  });

  // Set secure HttpOnly cookie
  res.cookie('trustvault_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 2 * 60 * 60 * 1000,
  });

  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
      full_name: user.full_name,
      department: user.department,
      must_change_password: user.must_change_password,
      created_at: user.created_at,
    },
  });
});

router.post('/auth/logout', requireAuthenticatedUser, (req: Request, res: Response): void => {
  db.appendAuditEvent({
    actor_user_id: req.auth!.userId,
    actor_email: req.auth!.email,
    action: 'LOGOUT',
    document_id: null,
    target_user_id: null,
    outcome: 'SUCCESS',
    reason_code: 'SESSION_TERMINATED',
    request_id: req.requestId!,
  });

  res.clearCookie('trustvault_token');
  res.json({ success: true, message: 'Logged out successfully.' });
});

router.get('/auth/me', requireAuthenticatedUser, (req: Request, res: Response): void => {
  const user = req.auth!.user;
  res.json({
    id: user.id,
    email: user.email,
    role: user.role,
    full_name: user.full_name,
    department: user.department,
    must_change_password: user.must_change_password,
    created_at: user.created_at,
    last_login_at: user.last_login_at,
  });
});

router.post('/auth/change-password', requireAuthenticatedUser, (req: Request, res: Response): void => {
  const { currentPassword, newPassword } = req.body;
  const user = req.auth!.user;

  if (!currentPassword || !newPassword) {
    res.status(400).json({ error: 'MISSING_FIELDS', message: 'Current and new password are required.' });
    return;
  }

  if (newPassword.length < 10) {
    res.status(400).json({
      error: 'WEAK_PASSWORD',
      message: 'Password must be at least 10 characters long and contain letters, numbers, and symbols.',
    });
    return;
  }

  if (!verifyPassword(currentPassword, user.password_hash)) {
    db.appendAuditEvent({
      actor_user_id: user.id,
      actor_email: user.email,
      action: 'PASSWORD_CHANGE_FAILED',
      document_id: null,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: 'CURRENT_PASSWORD_INCORRECT',
      request_id: req.requestId!,
    });

    res.status(400).json({ error: 'INCORRECT_PASSWORD', message: 'Current password is incorrect.' });
    return;
  }

  const newHash = hashPassword(newPassword);
  db.updateUser(user.id, {
    password_hash: newHash,
    must_change_password: false,
  });

  db.appendAuditEvent({
    actor_user_id: user.id,
    actor_email: user.email,
    action: 'PASSWORD_CHANGED',
    document_id: null,
    target_user_id: null,
    outcome: 'SUCCESS',
    reason_code: 'PASSWORD_ROTATED',
    request_id: req.requestId!,
  });

  res.json({ success: true, message: 'Password updated successfully.' });
});

// ==========================================
// DOCUMENT ENDPOINTS (STRICT AUTHORIZATION)
// ==========================================

// List accessible documents for current user
router.get('/documents', requireAuthenticatedUser, (req: Request, res: Response): void => {
  const user = req.auth!.user;
  const { search, category, owner, sort } = req.query;

  const allDocs = db.getDocuments();

  // Filter based on explicit access authorization:
  // User can only see documents they own OR have an active READ/EDIT permission for.
  // Admins can see metadata overview if explicitly in admin repository view, but here list user-permitted docs.
  const permittedDocs = allDocs.filter((doc) => {
    if (doc.owner_id === user.id) return true;
    if (user.role === 'ADMIN') return true; // Admin views metadata catalog
    const perm = db.findActivePermission(doc.id, user.id);
    return !!perm;
  });

  // Client filtering
  let filtered = permittedDocs;
  if (search && typeof search === 'string') {
    const s = search.toLowerCase();
    filtered = filtered.filter(
      (d) =>
        d.title.toLowerCase().includes(s) ||
        d.description.toLowerCase().includes(s) ||
        d.original_filename.toLowerCase().includes(s)
    );
  }

  if (category && typeof category === 'string' && category !== 'ALL') {
    filtered = filtered.filter((d) => d.category.toLowerCase() === category.toLowerCase());
  }

  if (owner && typeof owner === 'string') {
    const ownerUser = db.findUserByEmail(owner);
    if (ownerUser) {
      filtered = filtered.filter((d) => d.owner_id === ownerUser.id);
    }
  }

  // Attach caller's permission level for each document
  const results = filtered.map((doc) => {
    const isOwner = doc.owner_id === user.id;
    const perm = isOwner ? null : db.findActivePermission(doc.id, user.id);
    const ownerRecord = db.findUserById(doc.owner_id);

    return {
      id: doc.id,
      title: doc.title,
      description: doc.description,
      category: doc.category,
      owner_id: doc.owner_id,
      owner_email: ownerRecord ? ownerRecord.email : 'Unknown',
      owner_name: ownerRecord ? ownerRecord.full_name : 'Unknown',
      original_filename: doc.original_filename,
      mime_type: doc.mime_type,
      file_size: doc.file_size,
      sha256_checksum: doc.sha256_checksum,
      document_status: doc.document_status,
      created_at: doc.created_at,
      updated_at: doc.updated_at,
      is_owner: isOwner,
      user_permission: isOwner ? 'OWNER' : perm ? perm.permission_level : user.role === 'ADMIN' ? 'METADATA_ONLY' : 'NONE',
    };
  });

  res.json({ documents: results, total: results.length });
});

// Upload a new document (Owner / Admin)
router.post('/documents', requireAuthenticatedUser, upload.single('file'), (req: Request, res: Response): void => {
  const user = req.auth!.user;
  const file = req.file;
  const { title, description, category } = req.body;

  if (!file) {
    res.status(400).json({ error: 'FILE_REQUIRED', message: 'No file provided in request.' });
    return;
  }

  if (!title || !title.trim()) {
    res.status(400).json({ error: 'TITLE_REQUIRED', message: 'Document title is required.' });
    return;
  }

  // Safe filename sanitization
  const safeOriginalName = sanitizeFilename(file.originalname);
  const ext = path.extname(safeOriginalName).toLowerCase();

  // Validate magic bytes & size
  const magicValidation = validateFileMagicBytes(file.buffer, ext);
  if (!magicValidation.valid) {
    db.appendAuditEvent({
      actor_user_id: user.id,
      actor_email: user.email,
      action: 'INVALID_FILE_UPLOAD',
      document_id: null,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: 'MAGIC_BYTE_VALIDATION_FAILED',
      request_id: req.requestId!,
      metadata: { originalname: safeOriginalName, error: magicValidation.reason },
    });

    res.status(400).json({
      error: 'INVALID_FILE_SIGNATURE',
      message: magicValidation.reason || 'File validation failed.',
    });
    return;
  }

  // Generate randomized storage identifier
  const storageId = `tv_doc_${crypto.randomUUID()}${ext}`;
  const storagePath = path.join(DOCUMENTS_DIR, storageId);

  // Write file securely
  try {
    fs.writeFileSync(storagePath, file.buffer);
  } catch (err) {
    console.error('File write error:', err);
    res.status(500).json({ error: 'STORAGE_FAILURE', message: 'Failed to write document to secure storage.' });
    return;
  }

  const checksum = computeSha256(file.buffer.toString('binary'));

  const newDoc = db.createDocument({
    title: title.trim(),
    description: (description || '').trim(),
    category: category || 'General',
    owner_id: user.id,
    original_filename: safeOriginalName,
    storage_path: storageId,
    mime_type: file.mimetype || 'application/octet-stream',
    file_size: file.size,
    sha256_checksum: checksum,
    document_status: 'ACTIVE',
  });

  db.appendAuditEvent({
    actor_user_id: user.id,
    actor_email: user.email,
    action: 'DOCUMENT_UPLOAD',
    document_id: newDoc.id,
    target_user_id: null,
    outcome: 'SUCCESS',
    reason_code: 'DOCUMENT_ENCRYPTED_AND_SAVED',
    request_id: req.requestId!,
    metadata: {
      filename: safeOriginalName,
      size: file.size,
      checksum,
      category: newDoc.category,
    },
  });

  res.status(201).json({
    document: {
      id: newDoc.id,
      title: newDoc.title,
      description: newDoc.description,
      category: newDoc.category,
      owner_id: newDoc.owner_id,
      original_filename: newDoc.original_filename,
      mime_type: newDoc.mime_type,
      file_size: newDoc.file_size,
      sha256_checksum: newDoc.sha256_checksum,
      document_status: newDoc.document_status,
      created_at: newDoc.created_at,
    },
  });
});

// Get document details (READ authorization required)
router.get('/documents/:id', requireAuthenticatedUser, (req: Request, res: Response): void => {
  const docId = req.params.id;
  const user = req.auth!.user;

  const doc = db.findDocumentById(docId);
  if (!doc) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Document does not exist or has been removed.' });
    return;
  }

  // Authorization check
  const access = checkDocumentReadAccess(user, doc);
  if (!access.allowed && user.role !== 'ADMIN') {
    db.appendAuditEvent({
      actor_user_id: user.id,
      actor_email: user.email,
      action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      document_id: doc.id,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: 'INSUFFICIENT_DOCUMENT_READ_PERMISSION',
      request_id: req.requestId!,
    });

    res.status(403).json({
      error: 'ACCESS_DENIED',
      message: 'You do not have permission to view this document.',
    });
    return;
  }

  const isOwner = doc.owner_id === user.id;
  const perm = isOwner ? null : db.findActivePermission(doc.id, user.id);
  const ownerRecord = db.findUserById(doc.owner_id);

  db.appendAuditEvent({
    actor_user_id: user.id,
    actor_email: user.email,
    action: 'DOCUMENT_READ',
    document_id: doc.id,
    target_user_id: null,
    outcome: 'SUCCESS',
    reason_code: 'METADATA_INSPECTED',
    request_id: req.requestId!,
  });

  res.json({
    id: doc.id,
    title: doc.title,
    description: doc.description,
    category: doc.category,
    owner_id: doc.owner_id,
    owner_email: ownerRecord ? ownerRecord.email : 'Unknown',
    owner_name: ownerRecord ? ownerRecord.full_name : 'Unknown',
    original_filename: doc.original_filename,
    mime_type: doc.mime_type,
    file_size: doc.file_size,
    sha256_checksum: doc.sha256_checksum,
    document_status: doc.document_status,
    created_at: doc.created_at,
    updated_at: doc.updated_at,
    is_owner: isOwner,
    user_permission: isOwner ? 'OWNER' : perm ? perm.permission_level : user.role === 'ADMIN' ? 'METADATA_ONLY' : 'NONE',
  });
});

// Document Preview endpoint (READ access strictly required)
router.get('/documents/:id/preview', requireAuthenticatedUser, (req: Request, res: Response): void => {
  const docId = req.params.id;
  const user = req.auth!.user;

  const doc = db.findDocumentById(docId);
  if (!doc) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Document not found.' });
    return;
  }

  const access = checkDocumentReadAccess(user, doc);
  if (!access.allowed) {
    db.appendAuditEvent({
      actor_user_id: user.id,
      actor_email: user.email,
      action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      document_id: doc.id,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: 'PREVIEW_ACCESS_REVOKED_OR_DENIED',
      request_id: req.requestId!,
    });

    res.status(403).json({ error: 'ACCESS_DENIED', message: 'You do not have active READ permission for this document.' });
    return;
  }

  const filePath = path.join(DOCUMENTS_DIR, doc.storage_path);
  if (!fs.existsSync(filePath)) {
    res.status(404).json({ error: 'STORAGE_MISSING', message: 'Underlying document file not found.' });
    return;
  }

  db.appendAuditEvent({
    actor_user_id: user.id,
    actor_email: user.email,
    action: 'DOCUMENT_PREVIEW',
    document_id: doc.id,
    target_user_id: null,
    outcome: 'SUCCESS',
    reason_code: 'FILE_PREVIEW_STREAMED',
    request_id: req.requestId!,
  });

  res.setHeader('Content-Type', doc.mime_type);
  res.setHeader('Content-Disposition', `inline; filename="${doc.original_filename}"`);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  fs.createReadStream(filePath).pipe(res);
});

// Document Download endpoint (READ access strictly required)
router.get('/documents/:id/download', requireAuthenticatedUser, (req: Request, res: Response): void => {
  const docId = req.params.id;
  const user = req.auth!.user;

  const doc = db.findDocumentById(docId);
  if (!doc) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Document not found.' });
    return;
  }

  const access = checkDocumentReadAccess(user, doc);
  if (!access.allowed) {
    db.appendAuditEvent({
      actor_user_id: user.id,
      actor_email: user.email,
      action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      document_id: doc.id,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: 'DOWNLOAD_REVOKED_OR_FORBIDDEN',
      request_id: req.requestId!,
    });

    res.status(403).json({ error: 'ACCESS_DENIED', message: 'Permission denied. You cannot download this document.' });
    return;
  }

  const filePath = path.join(DOCUMENTS_DIR, doc.storage_path);
  if (!fs.existsSync(filePath)) {
    res.status(404).json({ error: 'STORAGE_MISSING', message: 'Document storage file missing.' });
    return;
  }

  db.appendAuditEvent({
    actor_user_id: user.id,
    actor_email: user.email,
    action: 'DOCUMENT_DOWNLOAD',
    document_id: doc.id,
    target_user_id: null,
    outcome: 'SUCCESS',
    reason_code: 'CONFIDENTIAL_DOWNLOAD_DISPATCHED',
    request_id: req.requestId!,
    metadata: {
      filename: doc.original_filename,
      size: doc.file_size,
    },
  });

  res.setHeader('Content-Type', doc.mime_type);
  res.setHeader('Content-Disposition', `attachment; filename="${doc.original_filename}"`);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  fs.createReadStream(filePath).pipe(res);
});

// Document Edit endpoint (EDIT access strictly required)
router.put('/documents/:id', requireAuthenticatedUser, (req: Request, res: Response): void => {
  const docId = req.params.id;
  const user = req.auth!.user;
  const { title, description, category, content } = req.body;

  const doc = db.findDocumentById(docId);
  if (!doc) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Document not found.' });
    return;
  }

  const access = checkDocumentEditAccess(user, doc);
  if (!access.allowed) {
    db.appendAuditEvent({
      actor_user_id: user.id,
      actor_email: user.email,
      action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      document_id: doc.id,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: 'INSUFFICIENT_DOCUMENT_EDIT_PERMISSION',
      request_id: req.requestId!,
    });

    res.status(403).json({
      error: 'ACCESS_DENIED',
      message: 'You do not have EDIT permission for this document.',
    });
    return;
  }

  const updates: Partial<typeof doc> = {};
  if (title) updates.title = title.trim();
  if (description !== undefined) updates.description = description.trim();
  if (category) updates.category = category.trim();

  // If text content was updated in the editor
  if (content !== undefined && (doc.mime_type.startsWith('text/') || doc.original_filename.endsWith('.txt'))) {
    const filePath = path.join(DOCUMENTS_DIR, doc.storage_path);
    fs.writeFileSync(filePath, content, 'utf8');
    updates.file_size = Buffer.byteLength(content, 'utf8');
    updates.sha256_checksum = computeSha256(content);
  }

  const updated = db.updateDocument(doc.id, updates);

  db.appendAuditEvent({
    actor_user_id: user.id,
    actor_email: user.email,
    action: 'DOCUMENT_EDIT',
    document_id: doc.id,
    target_user_id: null,
    outcome: 'SUCCESS',
    reason_code: 'DOCUMENT_CONTENT_OR_METADATA_UPDATED',
    request_id: req.requestId!,
    metadata: { updates: Object.keys(updates) },
  });

  res.json({ document: updated });
});

// Document Delete endpoint (OWNER strictly required)
router.delete('/documents/:id', requireAuthenticatedUser, (req: Request, res: Response): void => {
  const docId = req.params.id;
  const user = req.auth!.user;

  const doc = db.findDocumentById(docId);
  if (!doc) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Document not found.' });
    return;
  }

  const ownership = checkDocumentOwnership(user, doc);
  if (!ownership.allowed) {
    db.appendAuditEvent({
      actor_user_id: user.id,
      actor_email: user.email,
      action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      document_id: doc.id,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: 'NON_OWNER_DELETE_ATTEMPT',
      request_id: req.requestId!,
    });

    res.status(403).json({
      error: 'ACCESS_DENIED',
      message: 'Only the document owner can delete this document.',
    });
    return;
  }

  db.softDeleteDocument(doc.id);

  db.appendAuditEvent({
    actor_user_id: user.id,
    actor_email: user.email,
    action: 'DOCUMENT_DELETE',
    document_id: doc.id,
    target_user_id: null,
    outcome: 'SUCCESS',
    reason_code: 'DOCUMENT_ARCHIVED_AND_DELETED',
    request_id: req.requestId!,
  });

  res.json({ success: true, message: 'Document deleted successfully.' });
});

// ==========================================
// PERMISSIONS & IMMEDIATE REVOCATION ENDPOINTS
// ==========================================

// List active permissions for document (Owner or Admin)
router.get('/documents/:id/permissions', requireAuthenticatedUser, (req: Request, res: Response): void => {
  const docId = req.params.id;
  const user = req.auth!.user;

  const doc = db.findDocumentById(docId);
  if (!doc) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Document not found.' });
    return;
  }

  if (doc.owner_id !== user.id && user.role !== 'ADMIN') {
    db.appendAuditEvent({
      actor_user_id: user.id,
      actor_email: user.email,
      action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      document_id: doc.id,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: 'NON_OWNER_PERMISSION_QUERY',
      request_id: req.requestId!,
    });

    res.status(403).json({ error: 'ACCESS_DENIED', message: 'Only document owners may manage permissions.' });
    return;
  }

  const permissions = db.getActivePermissions(doc.id).map((p) => {
    const grantee = db.findUserById(p.user_id);
    return {
      id: p.id,
      document_id: p.document_id,
      user_id: p.user_id,
      user_email: grantee ? grantee.email : 'Unknown',
      user_name: grantee ? grantee.full_name : 'Unknown',
      department: grantee ? grantee.department : 'Unknown',
      permission_level: p.permission_level,
      granted_at: p.granted_at,
    };
  });

  res.json({ permissions });
});

// Grant Permission (Owner only)
router.post('/documents/:id/permissions', requireAuthenticatedUser, (req: Request, res: Response): void => {
  const docId = req.params.id;
  const user = req.auth!.user;
  const { targetEmail, permissionLevel } = req.body;

  const doc = db.findDocumentById(docId);
  if (!doc) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Document not found.' });
    return;
  }

  // 1. Verify authenticated user owns the document
  if (doc.owner_id !== user.id) {
    db.appendAuditEvent({
      actor_user_id: user.id,
      actor_email: user.email,
      action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      document_id: doc.id,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: 'NON_OWNER_PERMISSION_GRANT_ATTEMPT',
      request_id: req.requestId!,
    });

    res.status(403).json({ error: 'ACCESS_DENIED', message: 'Only the document owner can grant permissions.' });
    return;
  }

  // 2. Resolve target account
  if (!targetEmail) {
    res.status(400).json({ error: 'EMAIL_REQUIRED', message: 'Target user email is required.' });
    return;
  }

  const targetUser = db.findUserByEmail(targetEmail);
  if (!targetUser) {
    res.status(404).json({ error: 'TARGET_NOT_FOUND', message: `No registered account found with email: ${targetEmail}` });
    return;
  }

  // 3. Reject inactive accounts
  if (!targetUser.is_active) {
    res.status(400).json({ error: 'TARGET_INACTIVE', message: 'Cannot grant permissions to a deactivated account.' });
    return;
  }

  // Prevent self-grant (owner already has all permissions)
  if (targetUser.id === user.id) {
    res.status(400).json({ error: 'INVALID_TARGET', message: 'Owner already retains complete document authority.' });
    return;
  }

  // 4. Validate permission level
  if (permissionLevel !== 'READ' && permissionLevel !== 'EDIT') {
    res.status(400).json({ error: 'INVALID_LEVEL', message: 'Permission level must be either READ or EDIT.' });
    return;
  }

  // 6. Save permission in database transactionally
  const permission = db.grantPermission(doc.id, targetUser.id, permissionLevel, user.id);

  // 7. Record change in audit trail
  db.appendAuditEvent({
    actor_user_id: user.id,
    actor_email: user.email,
    action: 'PERMISSION_GRANTED',
    document_id: doc.id,
    target_user_id: targetUser.id,
    outcome: 'SUCCESS',
    reason_code: 'OWNER_EXPLICIT_DELEGATION',
    request_id: req.requestId!,
    metadata: {
      permission_level: permissionLevel,
      target_email: targetUser.email,
      document_title: doc.title,
    },
  });

  res.status(201).json({
    permission: {
      id: permission.id,
      document_id: permission.document_id,
      user_id: permission.user_id,
      user_email: targetUser.email,
      user_name: targetUser.full_name,
      permission_level: permission.permission_level,
      granted_at: permission.granted_at,
    },
  });
});

// Revoke Permission (Owner only) - IMMEDIATE ENFORCEMENT
router.delete('/documents/:id/permissions/:userId', requireAuthenticatedUser, (req: Request, res: Response): void => {
  const docId = req.params.id;
  const targetUserId = req.params.userId;
  const user = req.auth!.user;

  const doc = db.findDocumentById(docId);
  if (!doc) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Document not found.' });
    return;
  }

  // 1. Verify ownership
  if (doc.owner_id !== user.id && user.role !== 'ADMIN') {
    db.appendAuditEvent({
      actor_user_id: user.id,
      actor_email: user.email,
      action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      document_id: doc.id,
      target_user_id: targetUserId,
      outcome: 'DENIED',
      reason_code: 'NON_OWNER_PERMISSION_REVOCATION_ATTEMPT',
      request_id: req.requestId!,
    });

    res.status(403).json({ error: 'ACCESS_DENIED', message: 'Only the document owner can revoke permissions.' });
    return;
  }

  const targetUser = db.findUserById(targetUserId);

  // 3. Revoke transactionally
  const revoked = db.revokePermission(doc.id, targetUserId);
  if (!revoked) {
    res.status(404).json({ error: 'NO_ACTIVE_PERMISSION', message: 'No active permission found for this user.' });
    return;
  }

  // 4. Record who revoked it and when
  db.appendAuditEvent({
    actor_user_id: user.id,
    actor_email: user.email,
    action: 'PERMISSION_REVOKED',
    document_id: doc.id,
    target_user_id: targetUserId,
    outcome: 'SUCCESS',
    reason_code: 'IMMEDIATE_REVOCATION_EXECUTED',
    request_id: req.requestId!,
    metadata: {
      revoked_by_email: user.email,
      target_email: targetUser ? targetUser.email : 'Unknown',
      document_title: doc.title,
    },
  });

  res.json({ success: true, message: 'Permission revoked immediately. Subsequent access will be blocked.' });
});

// ==========================================
// AUDIT ACTIVITY CENTER & INTEGRITY
// ==========================================

// Audit Events (Admin or Owner auditing own docs)
router.get('/audit/events', requireAuthenticatedUser, (req: Request, res: Response): void => {
  const user = req.auth!.user;
  const { action, outcome, user_email, document_id, limit = '50', offset = '0' } = req.query;

  let events = db.getAuditEvents();

  // If ordinary user (non-admin), restrict to audit records involving themselves or documents they own
  if (user.role !== 'ADMIN') {
    const ownedDocs = new Set(db.getDocuments().filter((d) => d.owner_id === user.id).map((d) => d.id));
    events = events.filter(
      (e) =>
        e.actor_user_id === user.id ||
        e.target_user_id === user.id ||
        (e.document_id && ownedDocs.has(e.document_id))
    );
  }

  // Filtering
  if (action && typeof action === 'string') {
    events = events.filter((e) => e.action.toLowerCase() === action.toLowerCase());
  }

  if (outcome && typeof outcome === 'string') {
    events = events.filter((e) => e.outcome.toLowerCase() === outcome.toLowerCase());
  }

  if (user_email && typeof user_email === 'string') {
    events = events.filter((e) => e.actor_email.toLowerCase().includes(user_email.toLowerCase()));
  }

  if (document_id && typeof document_id === 'string') {
    events = events.filter((e) => e.document_id === document_id);
  }

  const start = parseInt(offset as string, 10) || 0;
  const count = parseInt(limit as string, 10) || 50;
  const paginated = events.slice(start, start + count);

  res.json({
    events: paginated,
    total: events.length,
    offset: start,
    limit: count,
  });
});

// Cryptographic hash chain verification endpoint
router.get('/audit/verify', requireAuthenticatedUser, (req: Request, res: Response): void => {
  const user = req.auth!.user;

  // Restricted to Administrator
  if (user.role !== 'ADMIN') {
    db.appendAuditEvent({
      actor_user_id: user.id,
      actor_email: user.email,
      action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      document_id: null,
      target_user_id: null,
      outcome: 'DENIED',
      reason_code: 'NON_ADMIN_AUDIT_VERIFY_ATTEMPT',
      request_id: req.requestId!,
    });

    res.status(403).json({ error: 'FORBIDDEN', message: 'Only system administrators can verify audit chain integrity.' });
    return;
  }

  const result = db.verifyAuditChain();

  db.appendAuditEvent({
    actor_user_id: user.id,
    actor_email: user.email,
    action: 'AUDIT_INTEGRITY_CHECK',
    document_id: null,
    target_user_id: null,
    outcome: result.is_valid ? 'SUCCESS' : 'DENIED',
    reason_code: result.is_valid ? 'CHAIN_INTEGRITY_CONFIRMED' : 'CHAIN_TAMPERING_DETECTED',
    request_id: req.requestId!,
    metadata: {
      verified_events: result.verified_events,
      total_events: result.total_events,
      is_valid: result.is_valid,
    },
  });

  res.json(result);
});

// ==========================================
// ADMIN CONSOLE ENDPOINTS
// ==========================================

router.get('/admin/metrics', requireAuthenticatedUser, requireAdminRole, (_req: Request, res: Response): void => {
  const users = db.getUsers();
  const docs = db.getDocuments();
  const audits = db.getAuditEvents();
  const securityEvents = db.getSecurityEvents();
  const integrity = db.verifyAuditChain();

  const totalUsers = users.length;
  const activeUsers = users.filter((u) => u.is_active).length;
  const totalDocuments = docs.length;

  const now = Date.now();
  const last24h = now - 24 * 60 * 60 * 1000;

  const recentUploads = audits.filter(
    (a) => a.action === 'DOCUMENT_UPLOAD' && new Date(a.timestamp).getTime() > last24h
  ).length;

  const recentDownloads = audits.filter(
    (a) => a.action === 'DOCUMENT_DOWNLOAD' && new Date(a.timestamp).getTime() > last24h
  ).length;

  const permissionChanges = audits.filter(
    (a) =>
      (a.action === 'PERMISSION_GRANTED' || a.action === 'PERMISSION_REVOKED') &&
      new Date(a.timestamp).getTime() > last24h
  ).length;

  const deniedAttempts = audits.filter(
    (a) => a.outcome === 'DENIED' && new Date(a.timestamp).getTime() > last24h
  ).length;

  const failedLogins = audits.filter(
    (a) => a.action === 'LOGIN_FAILURE' && new Date(a.timestamp).getTime() > last24h
  ).length;

  res.json({
    totalUsers,
    activeUsers,
    totalDocuments,
    recentUploads,
    recentDownloads,
    permissionChanges,
    deniedAttempts,
    failedLogins,
    unresolvedSecurityEvents: securityEvents.filter((s) => !s.resolved).length,
    auditIntegrityValid: integrity.is_valid,
    totalAuditEvents: audits.length,
    latestEventHash: integrity.latest_event_hash,
  });
});

// Admin User Management
router.get('/admin/users', requireAuthenticatedUser, requireAdminRole, (_req: Request, res: Response): void => {
  const users = db.getUsers().map((u) => ({
    id: u.id,
    email: u.email,
    role: u.role,
    full_name: u.full_name,
    department: u.department,
    is_active: u.is_active,
    must_change_password: u.must_change_password,
    created_at: u.created_at,
    last_login_at: u.last_login_at,
  }));
  res.json({ users });
});

router.post('/admin/users', requireAuthenticatedUser, requireAdminRole, (req: Request, res: Response): void => {
  const { email, full_name, department, role } = req.body;
  const admin = req.auth!.user;

  if (!email || !full_name) {
    res.status(400).json({ error: 'MISSING_FIELDS', message: 'Email and full name are required.' });
    return;
  }

  const existing = db.findUserByEmail(email);
  if (existing) {
    res.status(409).json({ error: 'EMAIL_EXISTS', message: 'A user with this email address already exists.' });
    return;
  }

  // Generate temporary password
  const tempPassword = `Temp#${crypto.randomBytes(4).toString('hex')}!`;
  const passwordHash = hashPassword(tempPassword);

  const newUser = db.createUser({
    email: email.trim().toLowerCase(),
    full_name: full_name.trim(),
    department: (department || 'General').trim(),
    role: role === 'ADMIN' || role === 'OWNER' ? role : 'VIEWER',
    is_active: true,
    must_change_password: true,
    password_hash: passwordHash,
    last_login_at: null,
  });

  db.appendAuditEvent({
    actor_user_id: admin.id,
    actor_email: admin.email,
    action: 'USER_CREATED',
    document_id: null,
    target_user_id: newUser.id,
    outcome: 'SUCCESS',
    reason_code: 'ADMIN_PROVISIONED_ACCOUNT',
    request_id: req.requestId!,
    metadata: {
      email: newUser.email,
      role: newUser.role,
    },
  });

  res.status(201).json({
    user: {
      id: newUser.id,
      email: newUser.email,
      full_name: newUser.full_name,
      department: newUser.department,
      role: newUser.role,
      is_active: newUser.is_active,
      must_change_password: newUser.must_change_password,
    },
    temporaryPassword: tempPassword,
  });
});

router.patch('/admin/users/:id', requireAuthenticatedUser, requireAdminRole, (req: Request, res: Response): void => {
  const targetId = req.params.id;
  const admin = req.auth!.user;
  const { is_active, role, reset_password } = req.body;

  const target = db.findUserById(targetId);
  if (!target) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'User not found.' });
    return;
  }

  // Prevent admin from deactivating self
  if (target.id === admin.id && is_active === false) {
    res.status(400).json({ error: 'INVALID_OPERATION', message: 'Administrators cannot deactivate their own account.' });
    return;
  }

  const updates: Partial<typeof target> = {};
  let tempPassword = '';

  if (typeof is_active === 'boolean') {
    updates.is_active = is_active;
  }

  if (role && (role === 'ADMIN' || role === 'OWNER' || role === 'VIEWER')) {
    updates.role = role;
  }

  if (reset_password) {
    tempPassword = `Reset#${crypto.randomBytes(4).toString('hex')}!`;
    updates.password_hash = hashPassword(tempPassword);
    updates.must_change_password = true;
  }

  const updated = db.updateUser(target.id, updates);

  db.appendAuditEvent({
    actor_user_id: admin.id,
    actor_email: admin.email,
    action: is_active === false ? 'USER_DEACTIVATED' : 'ADMIN_SECURITY_ACTION',
    document_id: null,
    target_user_id: target.id,
    outcome: 'SUCCESS',
    reason_code: 'ACCOUNT_MODIFIED_BY_ADMIN',
    request_id: req.requestId!,
    metadata: { updates: Object.keys(updates), target_email: target.email },
  });

  res.json({ user: updated, temporaryPassword: tempPassword || undefined });
});

router.get('/admin/security-events', requireAuthenticatedUser, requireAdminRole, (_req: Request, res: Response): void => {
  const events = db.getSecurityEvents();
  res.json({ events });
});

// ==========================================
// AUTOMATED SECURITY TEST SUITE RUNNER
// ==========================================

// Run all 30 security tests and return comprehensive audit test report
router.post('/tests/run', async (_req: Request, res: Response): Promise<void> => {
  try {
    const report = await runSecurityTestSuite();
    res.json(report);
  } catch (err: any) {
    console.error('Test suite runner failed:', err);
    res.status(500).json({ error: 'TEST_RUNNER_ERROR', message: err.message });
  }
});

export default router;
