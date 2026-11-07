import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import { DocumentItem, AuditEventItem } from '../types';
import {
  FileText,
  Upload,
  KeyRound,
  ShieldCheck,
  Download,
  Share2,
  Clock,
  ArrowRight,
} from 'lucide-react';

export const OwnerDashboardPage: React.FC = () => {
  const { user, navigateTo, showToast } = useAuth();
  const [ownedDocs, setOwnedDocs] = useState<DocumentItem[]>([]);
  const [recentAudits, setRecentAudits] = useState<AuditEventItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      try {
        const docRes = await api.listDocuments();
        const mine = docRes.documents.filter((d) => d.is_owner);
        setOwnedDocs(mine);

        const auditRes = await api.listAuditEvents({ limit: 10 });
        setRecentAudits(auditRes.events);
      } catch (err: any) {
        showToast('error', 'Error loading owner dashboard', err.message);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Owner Control Dashboard</h1>
          <p className="text-xs text-slate-400 mt-1">
            Governance workspace for <span className="text-white font-medium">{user?.full_name}</span>. Manage your confidential files and delegated access.
          </p>
        </div>

        <button
          onClick={() => navigateTo('upload')}
          className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-blue-600 rounded-md hover:bg-blue-500 transition-colors shadow-sm self-start sm:self-auto"
        >
          <Upload className="w-3.5 h-3.5" />
          <span>Upload Document</span>
        </button>
      </div>

      {/* Overview Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-1">
          <span className="text-xs text-slate-400">Documents Owned</span>
          <div className="text-2xl font-bold text-white font-mono tabular-nums">{ownedDocs.length}</div>
          <span className="text-[11px] text-slate-500">Subject to your explicit access control</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-1">
          <span className="text-xs text-slate-400">Zero-Trust Revocation</span>
          <div className="text-2xl font-bold text-amber-400 font-mono">IMMEDIATE</div>
          <span className="text-[11px] text-slate-500">Revocation enforced on next request</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-1">
          <span className="text-xs text-slate-400">Cryptographic Trail</span>
          <div className="text-2xl font-bold text-emerald-400 font-mono">CHAINED</div>
          <span className="text-[11px] text-slate-500">Every view and download logged</span>
        </div>
      </div>

      {/* Owned Documents Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between text-xs">
          <span className="font-semibold text-white">Your Confidential Documents</span>
          <button
            onClick={() => navigateTo('repository')}
            className="text-blue-400 hover:text-blue-300 transition-colors font-medium"
          >
            Browse All Repository
          </button>
        </div>

        {loading ? (
          <div className="p-8 text-center text-xs text-slate-500">Loading owned documents...</div>
        ) : ownedDocs.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500">
            You haven't uploaded any confidential documents yet.
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {ownedDocs.map((doc) => (
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
                    <span className="text-xs text-slate-400 font-mono">{doc.category}</span>
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                    File: {doc.original_filename} · {(doc.file_size / 1024).toFixed(1)} KB · Checksum: {doc.sha256_checksum.substring(0, 10)}...
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => navigateTo('access-management', doc.id)}
                    className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition-colors"
                  >
                    <Share2 className="w-3.5 h-3.5 text-blue-400" />
                    <span>Manage Access</span>
                  </button>

                  <button
                    onClick={() => navigateTo('document-detail', doc.id)}
                    className="px-2.5 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors"
                  >
                    Inspect
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recent Access Events on Your Documents */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
        <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
          Recent Access History on Your Files
        </h3>
        <div className="space-y-2 max-h-64 overflow-y-auto">
          {recentAudits.map((a) => (
            <div key={a.id} className="p-2.5 bg-slate-950 rounded border border-slate-800 text-xs flex items-center justify-between gap-4">
              <div className="min-w-0">
                <div className="text-white font-mono font-medium">{a.action}</div>
                <div className="text-[11px] text-slate-400 font-mono truncate">
                  Actor: {a.actor_email} · Reason: {a.reason_code}
                </div>
              </div>
              <div className="text-right shrink-0">
                <span
                  className={`text-[10px] uppercase font-mono px-1.5 py-0.5 rounded ${
                    a.outcome === 'SUCCESS' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'
                  }`}
                >
                  {a.outcome}
                </span>
                <div className="text-[10px] text-slate-500 font-mono mt-1 tabular-nums">
                  {new Date(a.timestamp).toLocaleTimeString()}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
