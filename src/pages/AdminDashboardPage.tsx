import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import { AdminMetrics } from '../types';
import {
  Users,
  FileText,
  Upload,
  Download,
  KeyRound,
  ShieldAlert,
  ShieldCheck,
  CheckCircle,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
} from 'lucide-react';

export const AdminDashboardPage: React.FC = () => {
  const { navigateTo, showToast } = useAuth();
  const [metrics, setMetrics] = useState<AdminMetrics | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchMetrics = async () => {
    setLoading(true);
    try {
      const data = await api.getAdminMetrics();
      setMetrics(data);
    } catch (err: any) {
      showToast('error', 'Metrics Error', err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">SecOps Administrative Command Console</h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time security telemetry, document governance metrics, and access anomaly counters from the database.
          </p>
        </div>

        <button
          onClick={fetchMetrics}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-900 border border-slate-700 hover:border-slate-600 rounded text-slate-300 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Metrics</span>
        </button>
      </div>

      {loading && !metrics ? (
        <div className="p-12 text-center text-xs text-slate-500">Querying database metrics...</div>
      ) : metrics ? (
        <>
          {/* Top Metric Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
              <div className="flex items-center justify-between text-slate-400 text-xs">
                <span>Registered Users</span>
                <Users className="w-4 h-4 text-blue-400" />
              </div>
              <div className="text-2xl font-bold text-white font-mono tabular-nums">
                {metrics.activeUsers} <span className="text-xs font-normal text-slate-500">/ {metrics.totalUsers} active</span>
              </div>
              <div className="text-[11px] text-slate-500">Managed directory accounts</div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
              <div className="flex items-center justify-between text-slate-400 text-xs">
                <span>Total Documents</span>
                <FileText className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="text-2xl font-bold text-white font-mono tabular-nums">
                {metrics.totalDocuments}
              </div>
              <div className="text-[11px] text-slate-500">Active encrypted files in vault</div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
              <div className="flex items-center justify-between text-slate-400 text-xs">
                <span>Denied Access Attempts</span>
                <ShieldAlert className="w-4 h-4 text-rose-400" />
              </div>
              <div className="text-2xl font-bold text-rose-400 font-mono tabular-nums">
                {metrics.deniedAttempts}
              </div>
              <div className="text-[11px] text-slate-500">Blocked in last 24h & audited</div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
              <div className="flex items-center justify-between text-slate-400 text-xs">
                <span>Cryptographic Chain</span>
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="text-2xl font-bold text-emerald-400 font-mono">
                {metrics.auditIntegrityValid ? 'VERIFIED' : 'TAMPERED'}
              </div>
              <div className="text-[11px] text-slate-500 font-mono tabular-nums">
                {metrics.totalAuditEvents} immutable events
              </div>
            </div>
          </div>

          {/* Activity Breakdown Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
              <div>
                <span className="text-xs text-slate-400">Recent Uploads (24h)</span>
                <div className="text-xl font-bold text-white font-mono tabular-nums mt-1">{metrics.recentUploads}</div>
              </div>
              <Upload className="w-6 h-6 text-blue-400/80" />
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
              <div>
                <span className="text-xs text-slate-400">Recent Downloads (24h)</span>
                <div className="text-xl font-bold text-white font-mono tabular-nums mt-1">{metrics.recentDownloads}</div>
              </div>
              <Download className="w-6 h-6 text-emerald-400/80" />
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
              <div>
                <span className="text-xs text-slate-400">Permission Delegations</span>
                <div className="text-xl font-bold text-white font-mono tabular-nums mt-1">{metrics.permissionChanges}</div>
              </div>
              <KeyRound className="w-6 h-6 text-amber-400/80" />
            </div>
          </div>

          {/* Direct Quick Action Modules */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
            <button
              onClick={() => navigateTo('user-management')}
              className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 p-4 rounded-xl text-left transition-colors flex items-center justify-between group"
            >
              <div>
                <h3 className="text-xs font-semibold text-white group-hover:text-blue-400 transition-colors">
                  User Lifecycle Management
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Provision temporary accounts, toggle status, and assign roles.
                </p>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-white transition-colors" />
            </button>

            <button
              onClick={() => navigateTo('security-events')}
              className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 p-4 rounded-xl text-left transition-colors flex items-center justify-between group"
            >
              <div>
                <h3 className="text-xs font-semibold text-white group-hover:text-blue-400 transition-colors">
                  Security Incident Console
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Investigate brute force login spikes and unauthorized probes.
                </p>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-white transition-colors" />
            </button>

            <button
              onClick={() => navigateTo('security-tests')}
              className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 p-4 rounded-xl text-left transition-colors flex items-center justify-between group"
            >
              <div>
                <h3 className="text-xs font-semibold text-white group-hover:text-emerald-400 transition-colors">
                  Automated Security Tests (30/30)
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Execute test suite verifying zero-trust authorization barriers.
                </p>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-white transition-colors" />
            </button>
          </div>
        </>
      ) : null}
    </div>
  );
};
