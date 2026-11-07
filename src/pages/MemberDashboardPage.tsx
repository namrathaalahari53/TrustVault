import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import { DocumentItem } from '../types';
import { FileText, Download, Eye, Lock, Shield, AlertCircle } from 'lucide-react';

export const MemberDashboardPage: React.FC = () => {
  const { user, navigateTo, showToast } = useAuth();
  const [sharedDocs, setSharedDocs] = useState<DocumentItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchShared = async () => {
      setLoading(true);
      try {
        const res = await api.listDocuments();
        // Documents that are shared with current user and not owned
        const shared = res.documents.filter((d) => !d.is_owner && d.user_permission !== 'NONE');
        setSharedDocs(shared);
      } catch (err: any) {
        showToast('error', 'Failed to load shared documents', err.message);
      } finally {
        setLoading(false);
      }
    };
    fetchShared();
  }, []);

  const handleDownload = async (doc: DocumentItem) => {
    try {
      await api.downloadDocument(doc.id, doc.original_filename);
      showToast('success', 'Download Started', `Downloading ${doc.original_filename}`);
    } catch (err: any) {
      showToast('error', 'Download Denied', err.message || 'Permission denied.');
    }
  };

  return (
    <div className="space-y-6">
      <div className="pb-4 border-b border-slate-800">
        <h1 className="text-xl font-bold text-white tracking-tight">Member Workspace</h1>
        <p className="text-xs text-slate-400 mt-1">
          Confidential documents explicitly shared with <span className="text-white font-medium">{user?.full_name}</span>. Access is subject to live authorization policies.
        </p>
      </div>

      {/* Role Policy Notice */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex items-start gap-3 text-xs">
        <Shield className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
        <div className="space-y-1 text-slate-300">
          <div className="font-semibold text-white">Your Authorization Scope: Member / Collaborator</div>
          <p className="text-slate-400 leading-relaxed">
            You can read and download documents where the owner has granted you <span className="text-emerald-400 font-mono font-medium">READ</span> permission. If granted <span className="text-amber-400 font-mono font-medium">EDIT</span> permission, you can also modify document contents. As a member, you cannot delete documents or grant permissions to others.
          </p>
        </div>
      </div>

      {/* Shared Documents List */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between text-xs">
          <span className="font-semibold text-white">Documents Shared With You ({sharedDocs.length})</span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-xs text-slate-500">Checking document authorizations...</div>
        ) : sharedDocs.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500">
            No documents have been explicitly shared with your account yet. Contact a document owner to request access.
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {sharedDocs.map((doc) => (
              <div key={doc.id} className="p-4 flex items-center justify-between gap-4 hover:bg-slate-800/30 transition-colors">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => navigateTo('document-detail', doc.id)}
                      className="font-semibold text-white hover:text-blue-400 text-xs transition-colors truncate"
                    >
                      {doc.title}
                    </button>
                    <span className="text-xs text-slate-500">·</span>
                    <span
                      className={`text-xs font-mono font-medium ${
                        doc.user_permission === 'EDIT' ? 'text-amber-400' : 'text-emerald-400'
                      }`}
                    >
                      {doc.user_permission}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                    Owner: {doc.owner_name} ({doc.owner_email}) · File: {doc.original_filename} ({(doc.file_size / 1024).toFixed(1)} KB)
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => navigateTo('document-detail', doc.id)}
                    className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition-colors"
                  >
                    <Eye className="w-3.5 h-3.5 text-slate-400" />
                    <span>View</span>
                  </button>

                  <button
                    onClick={() => handleDownload(doc)}
                    className="px-2.5 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium flex items-center gap-1.5 transition-colors shadow-sm"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
