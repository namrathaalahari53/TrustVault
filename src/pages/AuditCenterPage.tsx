import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import { AuditEventItem, ChainVerificationResult } from '../types';
import {
  ScrollText,
  ShieldCheck,
  ShieldAlert,
  Search,
  Filter,
  RefreshCw,
  CheckCircle2,
  AlertOctagon,
  Clock,
  ArrowRight,
  Database,
  Lock,
} from 'lucide-react';

export const AuditCenterPage: React.FC = () => {
  const { user, isAdmin, showToast } = useAuth();
  const [events, setEvents] = useState<AuditEventItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [verification, setVerification] = useState<ChainVerificationResult | null>(null);

  // Filters
  const [actionFilter, setActionFilter] = useState<string>('');
  const [outcomeFilter, setOutcomeFilter] = useState<string>('');
  const [emailFilter, setEmailFilter] = useState<string>('');

  const loadAuditData = async () => {
    setLoading(true);
    try {
      const data = await api.listAuditEvents({
        action: actionFilter || undefined,
        outcome: outcomeFilter || undefined,
        user_email: emailFilter || undefined,
        limit: 100,
      });
      setEvents(data.events);
      setTotal(data.total);
    } catch (err: any) {
      showToast('error', 'Failed to load audit records', err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyChain = async () => {
    if (!isAdmin) {
      showToast('error', 'Admin Role Required', 'Only system administrators can execute cryptographic hash chain audits.');
      return;
    }

    setVerifying(true);
    try {
      const result = await api.verifyAuditChain();
      setVerification(result);
      if (result.is_valid) {
        showToast('success', 'Chain Verified', `All ${result.verified_events} audit events cryptographically confirmed without tampering.`);
      } else {
        showToast('error', 'Tampering Detected', result.error_message || 'Audit chain broken.');
      }
    } catch (err: any) {
      showToast('error', 'Verification Failed', err.message);
    } finally {
      setVerifying(false);
    }
  };

  useEffect(() => {
    loadAuditData();
  }, [actionFilter, outcomeFilter, emailFilter]);

  return (
    <div className="space-y-6">
      {/* Page Title & Integrity Summary */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Audit Activity Center & Chained Proofs</h1>
          <p className="text-xs text-slate-400 mt-1">
            Tamper-resistant append-only ledger. Every successful and denied access attempt is cryptographically chained using SHA-256.
          </p>
        </div>

        {isAdmin && (
          <button
            onClick={handleVerifyChain}
            disabled={verifying}
            className="flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-white bg-blue-600 rounded-md hover:bg-blue-500 disabled:opacity-50 transition-colors shadow-sm self-start sm:self-auto"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
            <span>{verifying ? 'Verifying Hashes...' : 'Verify Cryptographic Integrity'}</span>
          </button>
        )}
      </div>

      {/* Cryptographic Proof Verification Card */}
      {verification && (
        <div
          className={`p-4 rounded-xl border text-xs space-y-2 ${
            verification.is_valid
              ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-200'
              : 'bg-rose-950/40 border-rose-800/80 text-rose-200'
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-semibold">
              {verification.is_valid ? (
                <>
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>Audit Chain Cryptographically Verified (No Tampering)</span>
                </>
              ) : (
                <>
                  <AlertOctagon className="w-4 h-4 text-rose-400" />
                  <span>Cryptographic Discontinuity Detected!</span>
                </>
              )}
            </div>
            <span className="font-mono text-[11px] text-slate-400">
              Verified: {verification.verified_events} / {verification.total_events} events
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono pt-1 text-slate-300">
            <div>
              <span className="text-slate-500">Genesis Hash: </span>
              <span className="text-slate-400 truncate inline-block max-w-[200px] align-bottom">
                {verification.genesis_hash}
              </span>
            </div>
            <div>
              <span className="text-slate-500">Latest Event Hash: </span>
              <span className="text-slate-400 truncate inline-block max-w-[200px] align-bottom">
                {verification.latest_event_hash}
              </span>
            </div>
          </div>

          {!verification.is_valid && (
            <div className="p-2.5 bg-rose-950 rounded border border-rose-800 text-rose-300 font-mono text-[11px]">
              Error: {verification.error_message} (Sequence #{verification.tampered_sequence})
            </div>
          )}
        </div>
      )}

      {/* Filter Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 bg-slate-900 border border-slate-800 p-3 rounded-lg text-xs">
        <div>
          <label className="block text-[11px] text-slate-400 mb-1">Filter by Action</label>
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-blue-500"
          >
            <option value="">All Actions</option>
            <option value="LOGIN_SUCCESS">LOGIN_SUCCESS</option>
            <option value="LOGIN_FAILURE">LOGIN_FAILURE</option>
            <option value="DOCUMENT_UPLOAD">DOCUMENT_UPLOAD</option>
            <option value="DOCUMENT_READ">DOCUMENT_READ</option>
            <option value="DOCUMENT_DOWNLOAD">DOCUMENT_DOWNLOAD</option>
            <option value="DOCUMENT_EDIT">DOCUMENT_EDIT</option>
            <option value="DOCUMENT_DELETE">DOCUMENT_DELETE</option>
            <option value="PERMISSION_GRANTED">PERMISSION_GRANTED</option>
            <option value="PERMISSION_REVOKED">PERMISSION_REVOKED</option>
            <option value="UNAUTHORIZED_ACCESS_ATTEMPT">UNAUTHORIZED_ACCESS_ATTEMPT</option>
            <option value="USER_CREATED">USER_CREATED</option>
            <option value="USER_DEACTIVATED">USER_DEACTIVATED</option>
          </select>
        </div>

        <div>
          <label className="block text-[11px] text-slate-400 mb-1">Filter by Outcome</label>
          <select
            value={outcomeFilter}
            onChange={(e) => setOutcomeFilter(e.target.value)}
            className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-blue-500"
          >
            <option value="">All Outcomes (Success & Denied)</option>
            <option value="SUCCESS">SUCCESS</option>
            <option value="DENIED">DENIED</option>
          </select>
        </div>

        <div>
          <label className="block text-[11px] text-slate-400 mb-1">Actor Email</label>
          <input
            type="text"
            value={emailFilter}
            onChange={(e) => setEmailFilter(e.target.value)}
            placeholder="Search email..."
            className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between text-xs">
          <span className="font-semibold text-white">Immutable Event Ledger</span>
          <span className="font-mono text-slate-400 tabular-nums">Total Records: {total}</span>
        </div>

        {loading ? (
          <div className="p-12 text-center text-xs text-slate-500">Loading audit records from database...</div>
        ) : events.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-500">No audit events match your active filters.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 font-mono text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3"># Seq</th>
                  <th className="py-2.5 px-3">Timestamp (UTC)</th>
                  <th className="py-2.5 px-3">Action</th>
                  <th className="py-2.5 px-3">Outcome</th>
                  <th className="py-2.5 px-3">Actor Email</th>
                  <th className="py-2.5 px-3">Target / Doc</th>
                  <th className="py-2.5 px-3">Reason Code</th>
                  <th className="py-2.5 px-3">Event Hash (SHA-256)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 font-mono text-[11px]">
                {events.map((evt) => (
                  <tr key={evt.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2.5 px-3 text-slate-400 tabular-nums">#{evt.sequence_number}</td>
                    <td className="py-2.5 px-3 text-slate-400 tabular-nums whitespace-nowrap">
                      {new Date(evt.timestamp).toISOString().replace('T', ' ').substring(0, 19)}
                    </td>
                    <td className="py-2.5 px-3 text-white font-medium">{evt.action}</td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-mono ${
                          evt.outcome === 'SUCCESS'
                            ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/50'
                            : 'bg-rose-950/80 text-rose-400 border border-rose-800/50'
                        }`}
                      >
                        {evt.outcome}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 max-w-[160px] truncate">{evt.actor_email}</td>
                    <td className="py-2.5 px-3 text-slate-400 max-w-[140px] truncate">
                      {evt.document_id || evt.target_user_id || '—'}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 truncate max-w-[140px]">{evt.reason_code}</td>
                    <td className="py-2.5 px-3 text-slate-500 max-w-[120px] truncate" title={evt.event_hash}>
                      {evt.event_hash.substring(0, 12)}...
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 text-[11px] text-slate-500 flex items-start gap-2">
        <Lock className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
        <div>
          <span className="text-slate-300 font-semibold">Audit Integrity Disclosures: </span>
          Audit records are strictly append-only in the application layer. Each event records the previous event's SHA-256 hash and its own canonical hash. While database root administrators could theoretically recompute an entire chain, no application user or API endpoint can edit, tamper, or delete past events.
        </div>
      </div>
    </div>
  );
};
