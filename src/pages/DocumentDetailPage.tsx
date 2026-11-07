import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import { DocumentItem, DocumentPermissionItem, AuditEventItem } from '../types';
import {
  FileText,
  Download,
  Share2,
  Trash2,
  Edit3,
  ShieldCheck,
  ShieldAlert,
  ArrowLeft,
  User,
  Clock,
  HardDrive,
  Hash,
  AlertCircle,
  CheckCircle,
  X,
  Plus,
} from 'lucide-react';

export const DocumentDetailPage: React.FC = () => {
  const { user, selectedDocId, navigateTo, showToast } = useAuth();
  const [doc, setDoc] = useState<DocumentItem | null>(null);
  const [permissions, setPermissions] = useState<DocumentPermissionItem[]>([]);
  const [audits, setAudits] = useState<AuditEventItem[]>([]);
  const [previewContent, setPreviewContent] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [previewLoading, setPreviewLoading] = useState<boolean>(false);
  const [isEditing, setIsEditing] = useState<boolean>(false);
  const [editTitle, setEditTitle] = useState('');
  const [editDesc, setEditDesc] = useState('');
  const [editContent, setEditContent] = useState('');

  // Permission grant form state
  const [grantEmail, setGrantEmail] = useState('');
  const [grantLevel, setGrantLevel] = useState<'READ' | 'EDIT'>('READ');
  const [isGranting, setIsGranting] = useState(false);

  const docId = selectedDocId || 'doc_iso_27001_soc2';

  const loadDocumentDetails = async () => {
    setLoading(true);
    try {
      const data = await api.getDocument(docId);
      setDoc(data);
      setEditTitle(data.title);
      setEditDesc(data.description);

      // Load permissions if owner or admin
      if (data.is_owner || user?.role === 'ADMIN') {
        const perms = await api.listPermissions(docId);
        setPermissions(perms.permissions);
      }

      // Load audit trail for this doc
      const auditData = await api.listAuditEvents({ document_id: docId, limit: 10 });
      setAudits(auditData.events);
    } catch (err: any) {
      showToast('error', 'Access Denied', err.message || 'Cannot view document details.');
      if (err.status === 403) {
        navigateTo('access-denied');
      }
    } finally {
      setLoading(false);
    }
  };

  const loadPreview = async () => {
    setPreviewLoading(true);
    try {
      const url = await api.getPreviewUrl(docId);
      const res = await fetch(url);
      const text = await res.text();
      setPreviewContent(text);
      setEditContent(text);
    } catch (err: any) {
      setPreviewContent(`[Preview Access Blocked: ${err.message}]`);
    } finally {
      setPreviewLoading(false);
    }
  };

  useEffect(() => {
    loadDocumentDetails();
    loadPreview();
  }, [docId]);

  const handleDownload = async () => {
    if (!doc) return;
    try {
      await api.downloadDocument(doc.id, doc.original_filename);
      showToast('success', 'Download Complete', `Decrypted and streamed ${doc.original_filename}`);
    } catch (err: any) {
      showToast('error', 'Download Denied', err.message || 'Permission denied.');
    }
  };

  const handleGrantPermission = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!grantEmail) return;

    setIsGranting(true);
    try {
      await api.grantPermission(docId, grantEmail.trim(), grantLevel);
      showToast('success', 'Permission Granted', `Granted ${grantLevel} access to ${grantEmail}`);
      setGrantEmail('');
      // Reload permissions & audit
      const perms = await api.listPermissions(docId);
      setPermissions(perms.permissions);
      const auditData = await api.listAuditEvents({ document_id: docId, limit: 10 });
      setAudits(auditData.events);
    } catch (err: any) {
      showToast('error', 'Grant Failed', err.message || 'Could not grant permission.');
    } finally {
      setIsGranting(false);
    }
  };

  const handleRevokePermission = async (userId: string, email: string) => {
    if (!window.confirm(`Immediately revoke access for ${email}? This takes effect immediately.`)) {
      return;
    }

    try {
      await api.revokePermission(docId, userId);
      showToast('success', 'Permission Revoked', `Access for ${email} has been revoked immediately.`);
      // Reload permissions & audit
      const perms = await api.listPermissions(docId);
      setPermissions(perms.permissions);
      const auditData = await api.listAuditEvents({ document_id: docId, limit: 10 });
      setAudits(auditData.events);
    } catch (err: any) {
      showToast('error', 'Revocation Failed', err.message || 'Could not revoke permission.');
    }
  };

  const handleSaveEdit = async () => {
    if (!doc) return;
    try {
      await api.updateDocument(doc.id, {
        title: editTitle,
        description: editDesc,
        content: editContent,
      });
      showToast('success', 'Document Saved', 'Updated metadata and content successfully.');
      setIsEditing(false);
      loadDocumentDetails();
      loadPreview();
    } catch (err: any) {
      showToast('error', 'Save Denied', err.message || 'You do not have EDIT permission for this document.');
    }
  };

  const handleDelete = async () => {
    if (!doc) return;
    if (!window.confirm(`Permanently delete "${doc.title}"?`)) return;

    try {
      await api.deleteDocument(doc.id);
      showToast('success', 'Document Deleted', 'Document marked deleted and archived.');
      navigateTo('repository');
    } catch (err: any) {
      showToast('error', 'Delete Denied', err.message || 'Only document owners can delete.');
    }
  };

  if (loading) {
    return (
      <div className="p-12 text-center text-xs text-slate-500">
        <div className="inline-block animate-spin rounded-full h-6 w-6 border-2 border-blue-500 border-t-transparent mb-2"></div>
        <div>Verifying document-level authorization policies...</div>
      </div>
    );
  }

  if (!doc) {
    return (
      <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-xl">
        <AlertCircle className="w-8 h-8 text-rose-400 mx-auto mb-2" />
        <h3 className="text-sm font-semibold text-white">Document Inaccessible</h3>
        <p className="text-xs text-slate-400 mt-1">This document does not exist or your access has been revoked.</p>
        <button
          onClick={() => navigateTo('repository')}
          className="mt-4 px-3 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md transition-colors"
        >
          Return to Repository
        </button>
      </div>
    );
  }

  const hasRead = doc.is_owner || doc.user_permission === 'READ' || doc.user_permission === 'EDIT';
  const hasEdit = doc.is_owner || doc.user_permission === 'EDIT';

  return (
    <div className="space-y-6">
      {/* Top back & actions */}
      <div className="flex items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <button
          onClick={() => navigateTo('repository')}
          className="flex items-center gap-1.5 text-xs font-medium text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Repository</span>
        </button>

        <div className="flex items-center gap-2">
          {hasEdit && (
            <button
              onClick={() => setIsEditing(!isEditing)}
              className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition-colors"
            >
              <Edit3 className="w-3.5 h-3.5 text-blue-400" />
              <span>{isEditing ? 'Cancel Edit' : 'Edit Document'}</span>
            </button>
          )}

          <button
            onClick={handleDownload}
            disabled={!hasRead}
            className={`px-3 py-1.5 rounded text-xs font-medium flex items-center gap-1.5 transition-colors ${
              hasRead
                ? 'bg-blue-600 hover:bg-blue-500 text-white shadow-sm'
                : 'bg-slate-800/40 text-slate-500 cursor-not-allowed border border-slate-800'
            }`}
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download</span>
          </button>

          {doc.is_owner && (
            <button
              onClick={handleDelete}
              className="p-1.5 rounded bg-slate-900 border border-slate-800 hover:bg-rose-950 hover:text-rose-400 text-slate-400 transition-colors"
              title="Delete Document"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Main Details & Metadata Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Metadata & In-App Preview */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            {isEditing ? (
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Title</label>
                  <input
                    type="text"
                    value={editTitle}
                    onChange={(e) => setEditTitle(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-md text-xs text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Description</label>
                  <textarea
                    rows={2}
                    value={editDesc}
                    onChange={(e) => setEditDesc(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-md text-xs text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>
            ) : (
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-lg font-bold text-white tracking-tight">{doc.title}</h2>
                  <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
                    <span>·</span>
                    <span className="text-blue-400 font-medium">
                      {doc.is_owner ? 'OWNER' : doc.user_permission}
                    </span>
                    <span>·</span>
                    <span>{doc.category}</span>
                  </div>
                </div>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                  {doc.description || 'No description provided.'}
                </p>
              </div>
            )}

            {/* Cryptographic and Storage Specs */}
            <div className="pt-3 border-t border-slate-800 grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
              <div>
                <span className="text-[11px] text-slate-500 block">File Name</span>
                <span className="font-mono text-slate-200 truncate block">{doc.original_filename}</span>
              </div>
              <div>
                <span className="text-[11px] text-slate-500 block">MIME Type</span>
                <span className="font-mono text-slate-200 block">{doc.mime_type}</span>
              </div>
              <div>
                <span className="text-[11px] text-slate-500 block">File Size</span>
                <span className="font-mono tabular-nums text-slate-200 block">{doc.file_size} bytes</span>
              </div>
              <div>
                <span className="text-[11px] text-slate-500 block">Document Owner</span>
                <span className="text-slate-200 truncate block">{doc.owner_name}</span>
              </div>
              <div>
                <span className="text-[11px] text-slate-500 block">Classification</span>
                <span className="text-emerald-400 font-mono block">STRICT_ZERO_TRUST</span>
              </div>
              <div>
                <span className="text-[11px] text-slate-500 block">Status</span>
                <span className="text-blue-400 font-mono block">{doc.document_status}</span>
              </div>
            </div>

            {/* Checksum display */}
            <div className="p-2.5 bg-slate-950/80 rounded border border-slate-800 text-[11px] font-mono flex items-center justify-between text-slate-400 overflow-x-auto">
              <span className="text-slate-500 mr-2 shrink-0">SHA-256 Checksum:</span>
              <span className="text-slate-300 truncate">{doc.sha256_checksum}</span>
            </div>
          </div>

          {/* Secure In-App Preview Section */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
                Secure File Content Preview
              </h3>
              <span className="text-[11px] text-slate-500">
                {hasRead ? 'Protected Stream Active' : 'Access Restricted'}
              </span>
            </div>

            {isEditing ? (
              <div className="space-y-2">
                <textarea
                  rows={10}
                  value={editContent}
                  onChange={(e) => setEditContent(e.target.value)}
                  className="w-full p-3 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-blue-500 leading-relaxed"
                />
                <button
                  onClick={handleSaveEdit}
                  className="px-3.5 py-1.5 text-xs font-medium text-white bg-blue-600 rounded-md hover:bg-blue-500 transition-colors shadow-sm"
                >
                  Save Document Changes
                </button>
              </div>
            ) : previewLoading ? (
              <div className="p-8 text-center text-xs text-slate-500">Decrypting file preview...</div>
            ) : (
              <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto max-h-96 whitespace-pre-wrap leading-relaxed">
                {previewContent || 'No preview available.'}
              </pre>
            )}
          </div>
        </div>

        {/* Right Column: Permission Controls & Audit Trail */}
        <div className="space-y-6">
          {/* Access Delegation & Revocation (Owner or Admin) */}
          {(doc.is_owner || user?.role === 'ADMIN') && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
                  Access Management
                </h3>
                <span className="text-[10px] text-amber-400 font-mono">IMMEDIATE REVOCATION</span>
              </div>

              {/* Grant access form */}
              {doc.is_owner && (
                <form onSubmit={handleGrantPermission} className="space-y-2.5">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">Share with User (Email)</label>
                    <input
                      type="email"
                      required
                      value={grantEmail}
                      onChange={(e) => setGrantEmail(e.target.value)}
                      placeholder="e.g. viewer_sarah@trustvault.security"
                      className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div className="flex gap-2">
                    <select
                      value={grantLevel}
                      onChange={(e) => setGrantLevel(e.target.value as any)}
                      className="px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded text-xs text-slate-200 focus:outline-none focus:border-blue-500 flex-1"
                    >
                      <option value="READ">READ (View & Download)</option>
                      <option value="EDIT">EDIT (Read & Modify)</option>
                    </select>
                    <button
                      type="submit"
                      disabled={isGranting}
                      className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-medium transition-colors shrink-0 flex items-center gap-1"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      <span>{isGranting ? 'Granting...' : 'Grant'}</span>
                    </button>
                  </div>
                </form>
              )}

              {/* Active Permissions List */}
              <div className="pt-2 border-t border-slate-800 space-y-2">
                <span className="text-[11px] font-semibold text-slate-400 block font-mono">
                  Active Delegations ({permissions.length})
                </span>

                {permissions.length === 0 ? (
                  <div className="text-[11px] text-slate-500 italic py-2">
                    No explicit delegations. Only owner retains access.
                  </div>
                ) : (
                  <div className="space-y-1.5 max-h-60 overflow-y-auto">
                    {permissions.map((perm) => (
                      <div
                        key={perm.id}
                        className="flex items-center justify-between p-2 bg-slate-950 rounded border border-slate-800 text-xs"
                      >
                        <div className="min-w-0 pr-2">
                          <div className="text-white font-medium truncate">{perm.user_name}</div>
                          <div className="text-[10px] text-slate-400 font-mono truncate">{perm.user_email}</div>
                          <div className="text-[10px] text-blue-400 font-mono mt-0.5">
                            Level: {perm.permission_level}
                          </div>
                        </div>

                        {doc.is_owner && (
                          <button
                            onClick={() => handleRevokePermission(perm.user_id, perm.user_email)}
                            className="px-2 py-1 text-[11px] font-medium text-rose-400 hover:bg-rose-950/60 rounded border border-rose-900/60 transition-colors shrink-0"
                            title="Revoke Access Immediately"
                          >
                            Revoke
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Document Access Audit Trail */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
              Document Audit Trail
            </h3>
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {audits.length === 0 ? (
                <div className="text-xs text-slate-500 py-3 text-center">No audit records for this file yet.</div>
              ) : (
                audits.map((a) => (
                  <div key={a.id} className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px] space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-slate-300 font-medium">{a.action}</span>
                      <span
                        className={`font-mono text-[10px] px-1 py-0.2 rounded ${
                          a.outcome === 'SUCCESS' ? 'text-emerald-400 bg-emerald-950/80' : 'text-rose-400 bg-rose-950/80'
                        }`}
                      >
                        {a.outcome}
                      </span>
                    </div>
                    <div className="text-slate-400 truncate font-mono">Actor: {a.actor_email}</div>
                    <div className="flex items-center justify-between text-slate-500 text-[10px] font-mono">
                      <span>Reason: {a.reason_code}</span>
                      <span className="tabular-nums">{new Date(a.timestamp).toLocaleTimeString()}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
