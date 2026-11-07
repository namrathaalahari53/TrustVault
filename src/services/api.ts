import {
  User,
  DocumentItem,
  DocumentPermissionItem,
  AuditEventItem,
  SecurityEventItem,
  ChainVerificationResult,
  AdminMetrics,
  SecurityReport,
} from '../types';

let inMemoryToken: string | null = null;
const TOKEN_KEY = 'trustvault_access_token';

export const api = {
  getToken(): string | null {
    if (inMemoryToken) return inMemoryToken;
    try {
      return localStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },

  setToken(token: string): void {
    inMemoryToken = token;
    try {
      localStorage.setItem(TOKEN_KEY, token);
    } catch {
      // Storage access may be blocked in iframe sandboxes; in-memory fallback maintains session
    }
  },

  clearToken(): void {
    inMemoryToken = null;
    try {
      localStorage.removeItem(TOKEN_KEY);
    } catch {
      // Ignore storage access error in restricted sandbox
    }
  },

  async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const token = this.getToken();
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    if (!(options.body instanceof FormData) && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    let res: Response;
    try {
      res = await fetch(`/api${endpoint}`, {
        ...options,
        headers,
      });
    } catch (networkErr: any) {
      throw new Error(networkErr.message || 'Network connection failed. Please check your connectivity.');
    }

    // Safely retrieve the response text first so that empty responses or non-JSON never crash with "Unexpected end of JSON input"
    let responseText = '';
    try {
      responseText = await res.text();
    } catch {
      responseText = '';
    }

    let data: any = null;
    if (responseText && responseText.trim().length > 0) {
      try {
        data = JSON.parse(responseText);
      } catch {
        // Non-JSON response (e.g., HTML error or plaintext)
        if (!res.ok) {
          throw new Error(`Server error (${res.status}): ${responseText.slice(0, 150)}`);
        }
        data = { message: responseText };
      }
    }

    if (!res.ok) {
      const errorMessage = data?.message || data?.error || `Request failed with status ${res.status}`;
      const err = new Error(errorMessage) as any;
      err.status = res.status;
      err.data = data;
      throw err;
    }

    // If response was 200/204 with an empty body, return an empty object to satisfy callers safely
    if (data === null || data === undefined) {
      return {} as T;
    }

    return data as T;
  },

  // Auth
  async login(email: string, password: string): Promise<{ token: string; user: User }> {
    const cleanEmail = email.trim().toLowerCase();
    const data = await this.request<{ token: string; user: User }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: cleanEmail, password }),
    });
    this.setToken(data.token);
    return data;
  },

  async register(payload: {
    email: string;
    password: string;
    full_name: string;
    department?: string;
    role?: 'OWNER' | 'VIEWER';
  }): Promise<{ token: string; user: User }> {
    const cleanEmail = payload.email.trim().toLowerCase();
    const data = await this.request<{ token: string; user: User }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        ...payload,
        email: cleanEmail,
      }),
    });
    this.setToken(data.token);
    return data;
  },

  async logout(): Promise<void> {
    try {
      await this.request('/auth/logout', { method: 'POST' });
    } finally {
      this.clearToken();
    }
  },

  async getMe(): Promise<User> {
    return this.request<User>('/auth/me');
  },

  async changePassword(currentPassword: string, newPassword: string): Promise<{ success: boolean; message: string }> {
    return this.request('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword }),
    });
  },

  // Documents
  async listDocuments(params?: { search?: string; category?: string; owner?: string }): Promise<{ documents: DocumentItem[]; total: number }> {
    const query = new URLSearchParams();
    if (params?.search) query.set('search', params.search);
    if (params?.category) query.set('category', params.category);
    if (params?.owner) query.set('owner', params.owner);
    return this.request<{ documents: DocumentItem[]; total: number }>(`/documents?${query.toString()}`);
  },

  async getDocument(id: string): Promise<DocumentItem> {
    return this.request<DocumentItem>(`/documents/${id}`);
  },

  async uploadDocument(formData: FormData): Promise<{ document: DocumentItem }> {
    return this.request<{ document: DocumentItem }>('/documents', {
      method: 'POST',
      body: formData,
    });
  },

  async updateDocument(id: string, updates: { title?: string; description?: string; category?: string; content?: string }): Promise<{ document: DocumentItem }> {
    return this.request<{ document: DocumentItem }>(`/documents/${id}`, {
      method: 'PUT',
      body: JSON.stringify(updates),
    });
  },

  async deleteDocument(id: string): Promise<{ success: boolean; message: string }> {
    return this.request(`/documents/${id}`, {
      method: 'DELETE',
    });
  },

  async downloadDocument(id: string, filename: string): Promise<void> {
    const token = this.getToken();
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const res = await fetch(`/api/documents/${id}/download`, { headers });
    if (!res.ok) {
      let errMsg = 'Failed to download document';
      try {
        const text = await res.text();
        if (text) {
          const json = JSON.parse(text);
          errMsg = json.message || json.error || errMsg;
        }
      } catch {}
      const err = new Error(errMsg) as any;
      err.status = res.status;
      throw err;
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  async getPreviewUrl(id: string): Promise<string> {
    const token = this.getToken();
    const res = await fetch(`/api/documents/${id}/preview`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      let msg = 'Preview unauthorized';
      try {
        const text = await res.text();
        if (text) {
          const json = JSON.parse(text);
          msg = json.message || json.error || msg;
        }
      } catch {}
      const err = new Error(msg) as any;
      err.status = res.status;
      throw err;
    }
    const blob = await res.blob();
    return window.URL.createObjectURL(blob);
  },

  // Permissions
  async listPermissions(documentId: string): Promise<{ permissions: DocumentPermissionItem[] }> {
    return this.request<{ permissions: DocumentPermissionItem[] }>(`/documents/${documentId}/permissions`);
  },

  async grantPermission(documentId: string, targetEmail: string, permissionLevel: 'READ' | 'EDIT'): Promise<{ permission: DocumentPermissionItem }> {
    return this.request<{ permission: DocumentPermissionItem }>(`/documents/${documentId}/permissions`, {
      method: 'POST',
      body: JSON.stringify({ targetEmail, permissionLevel }),
    });
  },

  async revokePermission(documentId: string, userId: string): Promise<{ success: boolean; message: string }> {
    return this.request(`/documents/${documentId}/permissions/${userId}`, {
      method: 'DELETE',
    });
  },

  // Audit
  async listAuditEvents(params?: { action?: string; outcome?: string; user_email?: string; document_id?: string; limit?: number }): Promise<{ events: AuditEventItem[]; total: number }> {
    const query = new URLSearchParams();
    if (params?.action) query.set('action', params.action);
    if (params?.outcome) query.set('outcome', params.outcome);
    if (params?.user_email) query.set('user_email', params.user_email);
    if (params?.document_id) query.set('document_id', params.document_id);
    if (params?.limit) query.set('limit', params.limit.toString());
    return this.request<{ events: AuditEventItem[]; total: number }>(`/audit/events?${query.toString()}`);
  },

  async verifyAuditChain(): Promise<ChainVerificationResult> {
    return this.request<ChainVerificationResult>('/audit/verify');
  },

  // Admin
  async getAdminMetrics(): Promise<AdminMetrics> {
    return this.request<AdminMetrics>('/admin/metrics');
  },

  async listUsers(): Promise<{ users: User[] }> {
    return this.request<{ users: User[] }>('/admin/users');
  },

  async createUser(payload: { email: string; full_name: string; department: string; role: string }): Promise<{ user: User; temporaryPassword?: string }> {
    return this.request('/admin/users', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async updateUser(id: string, updates: { is_active?: boolean; role?: string; reset_password?: boolean }): Promise<{ user: User; temporaryPassword?: string }> {
    return this.request(`/admin/users/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });
  },

  async getSecurityEvents(): Promise<{ events: SecurityEventItem[] }> {
    return this.request<{ events: SecurityEventItem[] }>('/admin/security-events');
  },

  // Tests Runner
  async runSecurityTests(): Promise<SecurityReport> {
    return this.request<SecurityReport>('/tests/run', {
      method: 'POST',
    });
  },
};
