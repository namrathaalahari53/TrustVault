import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

export interface UserRecord {
  id: string;
  email: string;
  password_hash: string;
  role: 'ADMIN' | 'OWNER' | 'VIEWER';
  is_active: boolean;
  must_change_password: boolean;
  full_name: string;
  department: string;
  created_at: string;
  last_login_at: string | null;
}

export interface DocumentRecord {
  id: string;
  title: string;
  description: string;
  category: string;
  owner_id: string;
  original_filename: string;
  storage_path: string;
  mime_type: string;
  file_size: number;
  sha256_checksum: string;
  document_status: 'ACTIVE' | 'ARCHIVED' | 'DELETED';
  created_at: string;
  updated_at: string;
}

export interface PermissionRecord {
  id: string;
  document_id: string;
  user_id: string;
  permission_level: 'READ' | 'EDIT';
  granted_by_user_id: string;
  granted_at: string;
  revoked_at: string | null;
}

export interface AuditEventRecord {
  id: string;
  event_id: string;
  sequence_number: number;
  actor_user_id: string | null;
  actor_email: string;
  action: string;
  document_id: string | null;
  target_user_id: string | null;
  timestamp: string;
  outcome: 'SUCCESS' | 'DENIED';
  reason_code: string;
  request_id: string;
  metadata: Record<string, any>;
  previous_hash: string;
  canonical_hash: string;
  event_hash: string;
}

export interface SecurityEventRecord {
  id: string;
  event_type: 'FAILED_LOGIN_SPIKE' | 'UNAUTHORIZED_ACCESS_ATTEMPT' | 'INTEGRITY_TAMPERING_DETECTED' | 'PRIVILEGE_ESCALATION_ATTEMPT' | 'INVALID_FILE_UPLOAD';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  actor_email: string;
  details: string;
  timestamp: string;
  resolved: boolean;
}

export interface DatabaseSchema {
  users: UserRecord[];
  documents: DocumentRecord[];
  permissions: PermissionRecord[];
  audit_events: AuditEventRecord[];
  security_events: SecurityEventRecord[];
}

const STORAGE_DIR = path.resolve(process.cwd(), 'storage');
const DB_FILE = path.join(STORAGE_DIR, 'trustvault_data.json');
const DOCUMENTS_DIR = path.join(STORAGE_DIR, 'documents');

// Ensure directories exist
if (!fs.existsSync(STORAGE_DIR)) {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
}
if (!fs.existsSync(DOCUMENTS_DIR)) {
  fs.mkdirSync(DOCUMENTS_DIR, { recursive: true });
}

export function hashPassword(password: string, salt?: string): string {
  const effectiveSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, effectiveSalt, 100000, 64, 'sha512').toString('hex');
  return `${effectiveSalt}:${hash}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  try {
    const parts = storedHash.split(':');
    if (parts.length !== 2) return false;
    const [salt, originalHash] = parts;
    const testHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return crypto.timingSafeEqual(Buffer.from(testHash, 'hex'), Buffer.from(originalHash, 'hex'));
  } catch {
    return false;
  }
}

// Canonical hash computation for audit records
export function computeCanonicalString(event: {
  sequence_number: number;
  actor_user_id: string | null;
  actor_email: string;
  action: string;
  document_id: string | null;
  target_user_id: string | null;
  timestamp: string;
  outcome: string;
  reason_code: string;
  metadata: Record<string, any>;
}): string {
  const sortedMeta = JSON.stringify(event.metadata || {}, Object.keys(event.metadata || {}).sort());
  return [
    event.sequence_number,
    event.actor_user_id || 'null',
    event.actor_email,
    event.action,
    event.document_id || 'null',
    event.target_user_id || 'null',
    event.timestamp,
    event.outcome,
    event.reason_code,
    sortedMeta,
  ].join('|');
}

export function computeSha256(data: string): string {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

export const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

class Database {
  private data: DatabaseSchema;

  constructor() {
    this.data = this.loadDatabase();
    if (this.data.users.length === 0) {
      this.seedInitialData();
    }
  }

  private loadDatabase(): DatabaseSchema {
    if (fs.existsSync(DB_FILE)) {
      try {
        const raw = fs.readFileSync(DB_FILE, 'utf8');
        return JSON.parse(raw);
      } catch (err) {
        console.error('Error reading database file, resetting:', err);
      }
    }
    return {
      users: [],
      documents: [],
      permissions: [],
      audit_events: [],
      security_events: [],
    };
  }

  private persist() {
    try {
      const tempPath = `${DB_FILE}.tmp`;
      fs.writeFileSync(tempPath, JSON.stringify(this.data, null, 2), 'utf8');
      fs.renameSync(tempPath, DB_FILE);
    } catch (err) {
      console.error('Failed to persist database:', err);
    }
  }

  private seedInitialData() {
    console.log('[TrustVault] Seeding secure initial accounts and default documents...');
    const now = new Date().toISOString();

    const users: UserRecord[] = [
      {
        id: 'usr_admin_01',
        email: 'admin@trustvault.security',
        password_hash: hashPassword('AdminPassword123!'),
        role: 'ADMIN',
        is_active: true,
        must_change_password: false,
        full_name: 'Arthur Vance (SecOps Lead)',
        department: 'Security Operations & Governance',
        created_at: now,
        last_login_at: null,
      },
      {
        id: 'usr_owner_alex',
        email: 'owner_alex@trustvault.security',
        password_hash: hashPassword('OwnerPassword123!'),
        role: 'OWNER',
        is_active: true,
        must_change_password: false,
        full_name: 'Alex Rivera (Principal Architect)',
        department: 'Core Infrastructure',
        created_at: now,
        last_login_at: null,
      },
      {
        id: 'usr_owner_elena',
        email: 'owner_elena@trustvault.security',
        password_hash: hashPassword('OwnerPassword123!'),
        role: 'OWNER',
        is_active: true,
        must_change_password: false,
        full_name: 'Elena Rostova (Compliance Officer)',
        department: 'Regulatory Compliance',
        created_at: now,
        last_login_at: null,
      },
      {
        id: 'usr_viewer_sarah',
        email: 'viewer_sarah@trustvault.security',
        password_hash: hashPassword('ViewerPassword123!'),
        role: 'VIEWER',
        is_active: true,
        must_change_password: false,
        full_name: 'Sarah Chen (Security Auditor)',
        department: 'Internal Audit',
        created_at: now,
        last_login_at: null,
      },
      {
        id: 'usr_editor_david',
        email: 'editor_david@trustvault.security',
        password_hash: hashPassword('EditorPassword123!'),
        role: 'VIEWER',
        is_active: true,
        must_change_password: false,
        full_name: 'David Keller (Senior DevSecOps)',
        department: 'Security Engineering',
        created_at: now,
        last_login_at: null,
      },
      {
        id: 'usr_unauth_john',
        email: 'unauth_john@trustvault.security',
        password_hash: hashPassword('JohnPassword123!'),
        role: 'VIEWER',
        is_active: true,
        must_change_password: false,
        full_name: 'John Miller (Junior Analyst)',
        department: 'Operations',
        created_at: now,
        last_login_at: null,
      },
      {
        id: 'usr_temp_user',
        email: 'temp_user@trustvault.security',
        password_hash: hashPassword('TempPassword123!'),
        role: 'VIEWER',
        is_active: true,
        must_change_password: true,
        full_name: 'Taylor Quinn (Contractor)',
        department: 'External Review',
        created_at: now,
        last_login_at: null,
      },
      {
        id: 'usr_inactive_mark',
        email: 'inactive_mark@trustvault.security',
        password_hash: hashPassword('InactivePassword123!'),
        role: 'VIEWER',
        is_active: false,
        must_change_password: false,
        full_name: 'Mark Hansen (Deactivated Account)',
        department: 'Vendor Risk',
        created_at: now,
        last_login_at: null,
      },
    ];

    this.data.users = users;

    // Seed sample physical documents in storage/documents
    const doc1Id = 'doc_iso_27001_soc2';
    const doc1Filename = `${doc1Id}.txt`;
    const doc1Path = path.join(DOCUMENTS_DIR, doc1Filename);
    const doc1Content = `TRUSTVAULT CONFIDENTIAL - STRICT ACCESS ONLY
Document: ISO 27001 & SOC 2 Type II System Security Plan
Classification: RESTRICTED
Owner: Alex Rivera (usr_owner_alex)

1. Executive Summary:
This document defines access control barriers, cryptographic key rotations, and identity verification mechanisms.
Only authorized security personnel may view or collaborate on this document.
Revocation must be enforced immediately across all gateways.`;
    fs.writeFileSync(doc1Path, doc1Content, 'utf8');

    const doc2Id = 'doc_q3_financial_audit';
    const doc2Filename = `${doc2Id}.txt`;
    const doc2Path = path.join(DOCUMENTS_DIR, doc2Filename);
    const doc2Content = `TRUSTVAULT CONFIDENTIAL
Document: Q3 Financial Controls & Ledger Audit
Classification: CONFIDENTIAL
Owner: Elena Rostova (usr_owner_elena)

Summary of internal capital allocations, penetration testing vendor fees, and cryptographic hardware module acquisitions.`;
    fs.writeFileSync(doc2Path, doc2Content, 'utf8');

    const documents: DocumentRecord[] = [
      {
        id: doc1Id,
        title: 'ISO 27001 & SOC 2 Security Policy',
        description: 'Comprehensive access control specifications, zero-trust perimeter controls, and key management policies.',
        category: 'Compliance & Security',
        owner_id: 'usr_owner_alex',
        original_filename: 'ISO_27001_SOC2_Plan.txt',
        storage_path: doc1Filename,
        mime_type: 'text/plain',
        file_size: Buffer.byteLength(doc1Content, 'utf8'),
        sha256_checksum: computeSha256(doc1Content),
        document_status: 'ACTIVE',
        created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
        updated_at: new Date(Date.now() - 86400000 * 3).toISOString(),
      },
      {
        id: doc2Id,
        title: 'Q3 Financial Controls & Ledger Audit',
        description: 'Internal risk assessment and regulatory compliance reporting for fiscal quarter audit.',
        category: 'Finance & Risk',
        owner_id: 'usr_owner_elena',
        original_filename: 'Q3_Financial_Controls.txt',
        storage_path: doc2Filename,
        mime_type: 'text/plain',
        file_size: Buffer.byteLength(doc2Content, 'utf8'),
        sha256_checksum: computeSha256(doc2Content),
        document_status: 'ACTIVE',
        created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
        updated_at: new Date(Date.now() - 86400000 * 2).toISOString(),
      },
    ];

    this.data.documents = documents;

    // Seed permissions:
    // doc1 (Alex): Sarah has READ, David has EDIT, John has NO PERMISSION
    this.data.permissions = [
      {
        id: 'perm_sarah_doc1',
        document_id: doc1Id,
        user_id: 'usr_viewer_sarah',
        permission_level: 'READ',
        granted_by_user_id: 'usr_owner_alex',
        granted_at: new Date(Date.now() - 86400000 * 2).toISOString(),
        revoked_at: null,
      },
      {
        id: 'perm_david_doc1',
        document_id: doc1Id,
        user_id: 'usr_editor_david',
        permission_level: 'EDIT',
        granted_by_user_id: 'usr_owner_alex',
        granted_at: new Date(Date.now() - 86400000 * 2).toISOString(),
        revoked_at: null,
      },
    ];

    // Seed initial Genesis and provisioning audit trail with hash chaining
    let prevHash = GENESIS_HASH;
    let seq = 1;

    const seedAudits = [
      {
        action: 'SYSTEM_GENESIS',
        actor_id: 'usr_admin_01',
        actor_email: 'admin@trustvault.security',
        doc_id: null,
        target_id: null,
        outcome: 'SUCCESS' as const,
        reason: 'SYSTEM_BOOTSTRAP',
        meta: { system: 'TrustVault Core 1.0', mode: 'STRICT_AUTHORIZATION' },
      },
      {
        action: 'USER_CREATED',
        actor_id: 'usr_admin_01',
        actor_email: 'admin@trustvault.security',
        doc_id: null,
        target_id: 'usr_owner_alex',
        outcome: 'SUCCESS' as const,
        reason: 'PROVISION_OWNER_ROLE',
        meta: { email: 'owner_alex@trustvault.security', role: 'OWNER' },
      },
      {
        action: 'DOCUMENT_UPLOAD',
        actor_id: 'usr_owner_alex',
        actor_email: 'owner_alex@trustvault.security',
        doc_id: doc1Id,
        target_id: null,
        outcome: 'SUCCESS' as const,
        reason: 'CONFIDENTIAL_DOC_STORED',
        meta: { filename: 'ISO_27001_SOC2_Plan.txt', size: Buffer.byteLength(doc1Content) },
      },
      {
        action: 'PERMISSION_GRANTED',
        actor_id: 'usr_owner_alex',
        actor_email: 'owner_alex@trustvault.security',
        doc_id: doc1Id,
        target_id: 'usr_viewer_sarah',
        outcome: 'SUCCESS' as const,
        reason: 'AUTHORIZED_READ_DELEGATION',
        meta: { permission_level: 'READ' },
      },
      {
        action: 'PERMISSION_GRANTED',
        actor_id: 'usr_owner_alex',
        actor_email: 'owner_alex@trustvault.security',
        doc_id: doc1Id,
        target_id: 'usr_editor_david',
        outcome: 'SUCCESS' as const,
        reason: 'AUTHORIZED_EDIT_DELEGATION',
        meta: { permission_level: 'EDIT' },
      },
    ];

    for (const item of seedAudits) {
      const ts = new Date(Date.now() - 86400000 * 2 + seq * 1000).toISOString();
      const canonicalStr = computeCanonicalString({
        sequence_number: seq,
        actor_user_id: item.actor_id,
        actor_email: item.actor_email,
        action: item.action,
        document_id: item.doc_id,
        target_user_id: item.target_id,
        timestamp: ts,
        outcome: item.outcome,
        reason_code: item.reason,
        metadata: item.meta,
      });
      const canonicalHash = computeSha256(canonicalStr);
      const eventHash = computeSha256(prevHash + canonicalHash);

      this.data.audit_events.push({
        id: `aud_${seq}`,
        event_id: crypto.randomUUID(),
        sequence_number: seq,
        actor_user_id: item.actor_id,
        actor_email: item.actor_email,
        action: item.action,
        document_id: item.doc_id,
        target_user_id: item.target_id,
        timestamp: ts,
        outcome: item.outcome,
        reason_code: item.reason,
        request_id: `req_init_${seq}`,
        metadata: item.meta,
        previous_hash: prevHash,
        canonical_hash: canonicalHash,
        event_hash: eventHash,
      });

      prevHash = eventHash;
      seq++;
    }

    this.persist();
  }

  // --- User Queries ---
  public getUsers(): UserRecord[] {
    return this.data.users;
  }

  public findUserById(id: string): UserRecord | undefined {
    return this.data.users.find((u) => u.id === id);
  }

  public findUserByEmail(email: string): UserRecord | undefined {
    return this.data.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
  }

  public createUser(user: Omit<UserRecord, 'id' | 'created_at'>): UserRecord {
    const newUser: UserRecord = {
      ...user,
      id: `usr_${crypto.randomUUID().slice(0, 8)}`,
      created_at: new Date().toISOString(),
    };
    this.data.users.push(newUser);
    this.persist();
    return newUser;
  }

  public updateUser(id: string, updates: Partial<UserRecord>): UserRecord | undefined {
    const user = this.findUserById(id);
    if (!user) return undefined;
    Object.assign(user, updates);
    this.persist();
    return user;
  }

  // --- Document Queries ---
  public getDocuments(): DocumentRecord[] {
    return this.data.documents.filter((d) => d.document_status !== 'DELETED');
  }

  public getAllDocumentsRaw(): DocumentRecord[] {
    return this.data.documents;
  }

  public findDocumentById(id: string): DocumentRecord | undefined {
    return this.data.documents.find((d) => d.id === id && d.document_status !== 'DELETED');
  }

  public createDocument(doc: Omit<DocumentRecord, 'id' | 'created_at' | 'updated_at'>): DocumentRecord {
    const newDoc: DocumentRecord = {
      ...doc,
      id: `doc_${crypto.randomUUID().slice(0, 8)}`,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    this.data.documents.push(newDoc);
    this.persist();
    return newDoc;
  }

  public updateDocument(id: string, updates: Partial<DocumentRecord>): DocumentRecord | undefined {
    const doc = this.findDocumentById(id);
    if (!doc) return undefined;
    Object.assign(doc, { ...updates, updated_at: new Date().toISOString() });
    this.persist();
    return doc;
  }

  public softDeleteDocument(id: string): boolean {
    const doc = this.findDocumentById(id);
    if (!doc) return false;
    doc.document_status = 'DELETED';
    doc.updated_at = new Date().toISOString();
    this.persist();
    return true;
  }

  // --- Permission Queries ---
  public getActivePermissions(documentId: string): PermissionRecord[] {
    return this.data.permissions.filter(
      (p) => p.document_id === documentId && p.revoked_at === null
    );
  }

  public findActivePermission(documentId: string, userId: string): PermissionRecord | undefined {
    return this.data.permissions.find(
      (p) => p.document_id === documentId && p.user_id === userId && p.revoked_at === null
    );
  }

  public grantPermission(
    documentId: string,
    userId: string,
    permissionLevel: 'READ' | 'EDIT',
    grantedByUserId: string
  ): PermissionRecord {
    // If an active permission already exists, update it transactionally
    const existing = this.findActivePermission(documentId, userId);
    if (existing) {
      existing.permission_level = permissionLevel;
      existing.granted_by_user_id = grantedByUserId;
      existing.granted_at = new Date().toISOString();
      this.persist();
      return existing;
    }

    const newPerm: PermissionRecord = {
      id: `perm_${crypto.randomUUID().slice(0, 8)}`,
      document_id: documentId,
      user_id: userId,
      permission_level: permissionLevel,
      granted_by_user_id: grantedByUserId,
      granted_at: new Date().toISOString(),
      revoked_at: null,
    };
    this.data.permissions.push(newPerm);
    this.persist();
    return newPerm;
  }

  public revokePermission(documentId: string, userId: string): boolean {
    const perm = this.findActivePermission(documentId, userId);
    if (!perm) return false;
    perm.revoked_at = new Date().toISOString();
    this.persist();
    return true;
  }

  // --- Audit Trail (Append-Only Chained) ---
  public appendAuditEvent(entry: {
    actor_user_id: string | null;
    actor_email: string;
    action: string;
    document_id: string | null;
    target_user_id: string | null;
    outcome: 'SUCCESS' | 'DENIED';
    reason_code: string;
    request_id: string;
    metadata?: Record<string, any>;
  }): AuditEventRecord {
    const lastEvent = this.data.audit_events[this.data.audit_events.length - 1];
    const prevHash = lastEvent ? lastEvent.event_hash : GENESIS_HASH;
    const seq = lastEvent ? lastEvent.sequence_number + 1 : 1;
    const ts = new Date().toISOString();
    const meta = entry.metadata || {};

    const canonicalStr = computeCanonicalString({
      sequence_number: seq,
      actor_user_id: entry.actor_user_id,
      actor_email: entry.actor_email,
      action: entry.action,
      document_id: entry.document_id,
      target_user_id: entry.target_user_id,
      timestamp: ts,
      outcome: entry.outcome,
      reason_code: entry.reason_code,
      metadata: meta,
    });

    const canonicalHash = computeSha256(canonicalStr);
    const eventHash = computeSha256(prevHash + canonicalHash);

    const record: AuditEventRecord = {
      id: `aud_${seq}`,
      event_id: crypto.randomUUID(),
      sequence_number: seq,
      actor_user_id: entry.actor_user_id,
      actor_email: entry.actor_email,
      action: entry.action,
      document_id: entry.document_id,
      target_user_id: entry.target_user_id,
      timestamp: ts,
      outcome: entry.outcome,
      reason_code: entry.reason_code,
      request_id: entry.request_id,
      metadata: meta,
      previous_hash: prevHash,
      canonical_hash: canonicalHash,
      event_hash: eventHash,
    };

    this.data.audit_events.push(record);

    // If an unauthorized access or failure occurs, also track in security_events
    if (entry.outcome === 'DENIED' || entry.action === 'UNAUTHORIZED_ACCESS_ATTEMPT') {
      this.data.security_events.push({
        id: `sec_${crypto.randomUUID().slice(0, 8)}`,
        event_type: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        severity: 'HIGH',
        actor_email: entry.actor_email,
        details: `Access attempt denied for action: ${entry.action} on document: ${entry.document_id || 'N/A'}. Reason: ${entry.reason_code}`,
        timestamp: ts,
        resolved: false,
      });
    }

    this.persist();
    return record;
  }

  public getAuditEvents(): AuditEventRecord[] {
    return [...this.data.audit_events].reverse();
  }

  public getSecurityEvents(): SecurityEventRecord[] {
    return [...this.data.security_events].reverse();
  }

  // Cryptographic audit chain verification
  public verifyAuditChain(): {
    is_valid: boolean;
    total_events: number;
    verified_events: number;
    tampered_event_id: string | null;
    tampered_sequence: number | null;
    error_message: string | null;
    genesis_hash: string;
    latest_event_hash: string;
    chain_head_timestamp: string | null;
  } {
    const events = this.data.audit_events;
    if (events.length === 0) {
      return {
        is_valid: true,
        total_events: 0,
        verified_events: 0,
        tampered_event_id: null,
        tampered_sequence: null,
        error_message: null,
        genesis_hash: GENESIS_HASH,
        latest_event_hash: GENESIS_HASH,
        chain_head_timestamp: null,
      };
    }

    let expectedPrevHash = GENESIS_HASH;

    for (let i = 0; i < events.length; i++) {
      const evt = events[i];

      // 1. Check sequence ordering
      if (evt.sequence_number !== i + 1) {
        return {
          is_valid: false,
          total_events: events.length,
          verified_events: i,
          tampered_event_id: evt.id,
          tampered_sequence: evt.sequence_number,
          error_message: `Sequence gap or ordering anomaly detected at index ${i}. Expected ${i + 1}, found ${evt.sequence_number}.`,
          genesis_hash: GENESIS_HASH,
          latest_event_hash: events[events.length - 1].event_hash,
          chain_head_timestamp: events[events.length - 1].timestamp,
        };
      }

      // 2. Check previous hash link
      if (evt.previous_hash !== expectedPrevHash) {
        return {
          is_valid: false,
          total_events: events.length,
          verified_events: i,
          tampered_event_id: evt.id,
          tampered_sequence: evt.sequence_number,
          error_message: `Cryptographic link broken at sequence ${evt.sequence_number}. Previous hash mismatch.`,
          genesis_hash: GENESIS_HASH,
          latest_event_hash: events[events.length - 1].event_hash,
          chain_head_timestamp: events[events.length - 1].timestamp,
        };
      }

      // 3. Recalculate canonical hash
      const recomputedCanonical = computeCanonicalString({
        sequence_number: evt.sequence_number,
        actor_user_id: evt.actor_user_id,
        actor_email: evt.actor_email,
        action: evt.action,
        document_id: evt.document_id,
        target_user_id: evt.target_user_id,
        timestamp: evt.timestamp,
        outcome: evt.outcome,
        reason_code: evt.reason_code,
        metadata: evt.metadata,
      });
      const recomputedCanonicalHash = computeSha256(recomputedCanonical);

      if (recomputedCanonicalHash !== evt.canonical_hash) {
        return {
          is_valid: false,
          total_events: events.length,
          verified_events: i,
          tampered_event_id: evt.id,
          tampered_sequence: evt.sequence_number,
          error_message: `Payload tampering detected at sequence ${evt.sequence_number}. Canonical data hash does not match content.`,
          genesis_hash: GENESIS_HASH,
          latest_event_hash: events[events.length - 1].event_hash,
          chain_head_timestamp: events[events.length - 1].timestamp,
        };
      }

      // 4. Recalculate event hash
      const recomputedEventHash = computeSha256(evt.previous_hash + recomputedCanonicalHash);
      if (recomputedEventHash !== evt.event_hash) {
        return {
          is_valid: false,
          total_events: events.length,
          verified_events: i,
          tampered_event_id: evt.id,
          tampered_sequence: evt.sequence_number,
          error_message: `Chained event hash mismatch at sequence ${evt.sequence_number}. Expected ${recomputedEventHash}, stored ${evt.event_hash}.`,
          genesis_hash: GENESIS_HASH,
          latest_event_hash: events[events.length - 1].event_hash,
          chain_head_timestamp: events[events.length - 1].timestamp,
        };
      }

      expectedPrevHash = evt.event_hash;
    }

    return {
      is_valid: true,
      total_events: events.length,
      verified_events: events.length,
      tampered_event_id: null,
      tampered_sequence: null,
      error_message: null,
      genesis_hash: GENESIS_HASH,
      latest_event_hash: events[events.length - 1].event_hash,
      chain_head_timestamp: events[events.length - 1].timestamp,
    };
  }

  // Simulation method specifically for automated testing (Test 30)
  public simulateAuditTamperingForTest(): { originalHash: string; tamperedId: string } | null {
    if (this.data.audit_events.length === 0) return null;
    const target = this.data.audit_events[0];
    const orig = target.action;
    target.action = 'TAMPERED_ACTION_FOR_TEST';
    // note: we intentionally do not recalculate the hash so verification fails
    return { originalHash: target.event_hash, tamperedId: target.id };
  }

  public revertAuditTamperingForTest(): void {
    if (this.data.audit_events.length === 0) return;
    this.data.audit_events[0].action = 'SYSTEM_GENESIS';
  }

  // Reset database for clean state during testing if requested
  public resetToSeeds(): void {
    this.data = {
      users: [],
      documents: [],
      permissions: [],
      audit_events: [],
      security_events: [],
    };
    this.seedInitialData();
  }
}

export const db = new Database();
export { DOCUMENTS_DIR, STORAGE_DIR };
