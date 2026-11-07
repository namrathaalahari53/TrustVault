export type UserRole = 'ADMIN' | 'OWNER' | 'VIEWER';
export type PermissionLevel = 'READ' | 'EDIT' | 'OWNER' | 'METADATA_ONLY' | 'NONE';

export interface User {
  id: string;
  email: string;
  role: UserRole;
  full_name: string;
  department: string;
  is_active: boolean;
  must_change_password: boolean;
  created_at: string;
  last_login_at?: string | null;
}

export interface DocumentItem {
  id: string;
  title: string;
  description: string;
  category: string;
  owner_id: string;
  owner_email: string;
  owner_name: string;
  original_filename: string;
  mime_type: string;
  file_size: number;
  sha256_checksum: string;
  document_status: 'ACTIVE' | 'ARCHIVED' | 'DELETED';
  created_at: string;
  updated_at: string;
  is_owner: boolean;
  user_permission: PermissionLevel;
}

export interface DocumentPermissionItem {
  id: string;
  document_id: string;
  user_id: string;
  user_email: string;
  user_name: string;
  department: string;
  permission_level: 'READ' | 'EDIT';
  granted_at: string;
}

export interface AuditEventItem {
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

export interface SecurityEventItem {
  id: string;
  event_type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  actor_email: string;
  details: string;
  timestamp: string;
  resolved: boolean;
}

export interface ChainVerificationResult {
  is_valid: boolean;
  total_events: number;
  verified_events: number;
  tampered_event_id: string | null;
  tampered_sequence: number | null;
  error_message: string | null;
  genesis_hash: string;
  latest_event_hash: string;
  chain_head_timestamp: string | null;
}

export interface AdminMetrics {
  totalUsers: number;
  activeUsers: number;
  totalDocuments: number;
  recentUploads: number;
  recentDownloads: number;
  permissionChanges: number;
  deniedAttempts: number;
  failedLogins: number;
  unresolvedSecurityEvents: number;
  auditIntegrityValid: boolean;
  totalAuditEvents: number;
  latestEventHash: string;
}

export interface TestCaseResult {
  id: number;
  name: string;
  category: 'AUTHENTICATION' | 'AUTHORIZATION' | 'REVOCATION' | 'AUDIT_INTEGRITY' | 'FILE_SECURITY' | 'IDOR_PROTECTION';
  expected: string;
  actual: string;
  status: 'PASS' | 'FAIL';
  execution_ms: number;
  details?: string;
}

export interface SecurityReport {
  summary: {
    total_tests: number;
    passed: number;
    failed: number;
    pass_percentage: number;
    total_execution_ms: number;
    executed_at: string;
    environment: string;
    engine: string;
  };
  results: TestCaseResult[];
}
