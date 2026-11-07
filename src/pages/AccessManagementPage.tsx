import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import { DocumentItem, DocumentPermissionItem } from '../types';
import { KeyRound, ShieldCheck, UserMinus, Plus, AlertCircle, FileText, CheckCircle } from 'lucide-react';

export const AccessManagementPage: React.FC = () => {
  const { user, selectedDocId, showToast } = useAuth();
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [activeDocId, setActiveDocId] = useState<string>(selectedDocId || '');
  const [permissions, setPermissions] = useState<DocumentPermissionItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [permsLoading, setPermsLoading] = useState<boolean>(false);

  // Grant form state
  const [targetEmail, setTargetEmail] = useState('');
  const [permLevel, setPermLevel] = useState<'READ' | 'EDIT'>('READ');
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    const loadDocs = async () => {
      try {
        const res = await api.listDocuments();
        // Only docs owned by current user (or all if admin)
        const manageable = res.documents.filter((d) => d.is_owner || user?.role === 'ADMIN');
        setDocuments(manageable);
        if (manageable.length > 0 && !activeDocId) {
          setActiveDocId(manageable[0].id);
        }
      } catch (err: any) {
        showToast('error', 'Failed to load documents', err.message);
      } finally {
        setLoading(false);
      }
    };
    loadDocs();
  }, []);

  useEffect(() => {
    if (!activeDocId) return;
    const loadPerms = async () => {
      setPermsLoading(true);
      try {
        const res = await api.listPermissions(activeDocId);
        setPermissions(res.permissions);
      } catch (err: any) {
        showToast('error', 'Could not fetch permissions', err.message);
      } finally {
        setPermsLoading(false);
      }
    };
    loadPerms();
  }, [activeDocId]);

  const handleGrant = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeDocId || !targetEmail) return;

    setIsSubmitting(true);
    try {
      await api.grantPermission(activeDocId, targetEmail.trim(), permLevel);
      showToast('success', 'Permission Granted', `Granted ${permLevel} access to ${targetEmail}`);
      setTargetEmail('');
      const res = await api.listPermissions(activeDocId);
      setPermissions(res.permissions);
    } catch (err: any) {
      showToast('error', 'Grant Failed', err.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRevoke = async (targetUserId: string, email: string) => {
    if (!activeDocId) return;
    if (!window.confirm(`Revoke document access immediately for ${email}?`)) return;

    try {
      await api.revokePermission(activeDocId, targetUserId);
      showToast('success', 'Access Revoked Immediately', `Subsequent requests from ${email} will return 403 Forbidden.`);
      const res = await api.listPermissions(activeDocId);
      setPermissions(res.permissions);
    } catch (err: any) {
      showToast('error', 'Revocation Failed', err.message);
    }
  };

  const currentDoc = documents.find((d) => d.id === activeDocId);

  return (
    <div className="space-y-6">
      <div className="pb-4 border-b border-slate-800">
        <h1 className="text-xl font-bold text-white tracking-tight">Access Control & Revocation Gateway</h1>
        <p className="text-xs text-slate-400 mt-1">
          Grant document-specific READ or EDIT permissions to collaborators. Revoked permissions terminate access immediately.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Document Selector */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
          <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
            Select Document
          </div>

          {loading ? (
            <div className="text-xs text-slate-500 py-4 text-center">Loading owned documents...</div>
          ) : documents.length === 0 ? (
            <div className="text-xs text-slate-500 py-4 text-center">
              No owned documents to manage. Upload a document first.
            </div>
          ) : (
            <div className="space-y-1.5 max-h-96 overflow-y-auto">
              {documents.map((d) => (
                <button
                  key={d.id}
                  onClick={() => setActiveDocId(d.id)}
                  className={`w-full text-left p-2.5 rounded-lg text-xs transition-colors flex flex-col gap-1 ${
                    activeDocId === d.id
                      ? 'bg-blue-600/15 text-blue-300 border border-blue-500/30'
                      : 'bg-slate-950/60 text-slate-400 hover:text-white hover:bg-slate-800/50 border border-transparent'
                  }`}
                >
                  <div className="font-medium text-white truncate">{d.title}</div>
                  <div className="text-[11px] text-slate-500 font-mono truncate">{d.original_filename}</div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Right 2 columns: Grant Form + Active Delegations */}
        <div className="lg:col-span-2 space-y-6">
          {currentDoc ? (
            <>
              {/* Grant Box */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-semibold text-white">
                    Delegate Access: <span className="text-blue-400">{currentDoc.title}</span>
                  </h2>
                  <span className="text-[10px] font-mono text-slate-500">ID: {currentDoc.id}</span>
                </div>

                <form onSubmit={handleGrant} className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="sm:col-span-2">
                    <label className="block text-xs font-medium text-slate-300 mb-1">
                      Target User Work Email
                    </label>
                    <input
                      type="email"
                      required
                      value={targetEmail}
                      onChange={(e) => setTargetEmail(e.target.value)}
                      placeholder="e.g. viewer_sarah@trustvault.security"
                      className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-md text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">Permission Level</label>
                    <select
                      value={permLevel}
                      onChange={(e) => setPermLevel(e.target.value as any)}
                      className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-md text-xs text-white focus:outline-none focus:border-blue-500"
                    >
                      <option value="READ">READ (View & Download)</option>
                      <option value="EDIT">EDIT (Read & Modify)</option>
                    </select>
                  </div>

                  <div className="sm:col-span-3 pt-1">
                    <button
                      type="submit"
                      disabled={isSubmitting}
                      className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-md text-xs font-medium transition-colors flex items-center gap-1.5"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      <span>{isSubmitting ? 'Granting Access...' : 'Grant Access Permission'}</span>
                    </button>
                  </div>
                </form>
              </div>

              {/* Active Collaborators */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
                    Active Granted Permissions ({permissions.length})
                  </h3>
                  <span className="text-[11px] text-emerald-400 font-mono">NO STALE TOKENS</span>
                </div>

                {permsLoading ? (
                  <div className="p-6 text-center text-xs text-slate-500">Querying permission ledger...</div>
                ) : permissions.length === 0 ? (
                  <div className="p-6 text-center bg-slate-950 rounded-lg text-xs text-slate-500">
                    No users currently have delegated access. Only the document owner ({currentDoc.owner_email}) can read or edit this document.
                  </div>
                ) : (
                  <div className="divide-y divide-slate-800 bg-slate-950 rounded-lg border border-slate-800 overflow-hidden">
                    {permissions.map((p) => (
                      <div key={p.id} className="p-3.5 flex items-center justify-between gap-4">
                        <div className="space-y-0.5">
                          <div className="font-semibold text-white text-xs">{p.user_name}</div>
                          <div className="text-[11px] text-slate-400 font-mono">{p.user_email}</div>
                          <div className="text-[11px] text-slate-500 font-mono">
                            Level: <span className="text-blue-400 font-semibold">{p.permission_level}</span> · Granted {new Date(p.granted_at).toLocaleDateString()}
                          </div>
                        </div>

                        <button
                          onClick={() => handleRevoke(p.user_id, p.user_email)}
                          className="px-3 py-1.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300 hover:bg-rose-900 text-xs font-medium transition-colors flex items-center gap-1.5"
                        >
                          <UserMinus className="w-3.5 h-3.5 text-rose-400" />
                          <span>Revoke Access</span>
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="p-12 text-center bg-slate-900 border border-slate-800 rounded-xl text-xs text-slate-500">
              Select a document from the left column to inspect and configure delegated permissions.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
