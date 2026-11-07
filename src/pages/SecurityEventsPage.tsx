import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import { SecurityEventItem } from '../types';
import { ShieldAlert, AlertTriangle, AlertCircle, CheckCircle, RefreshCw } from 'lucide-react';

export const SecurityEventsPage: React.FC = () => {
  const { showToast } = useAuth();
  const [events, setEvents] = useState<SecurityEventItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchSecurityEvents = async () => {
    setLoading(true);
    try {
      const res = await api.getSecurityEvents();
      setEvents(res.events);
    } catch (err: any) {
      showToast('error', 'Error loading security events', err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSecurityEvents();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Security Incident Investigation</h1>
          <p className="text-xs text-slate-400 mt-1">
            Telemetry on denied authorization requests, brute-force anomalies, and file signature rejections.
          </p>
        </div>

        <button
          onClick={fetchSecurityEvents}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-900 border border-slate-700 hover:border-slate-600 rounded text-slate-300 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Incidents</span>
        </button>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between text-xs">
          <span className="font-semibold text-white">Triggered Security Incidents ({events.length})</span>
          <span className="text-slate-400 font-mono text-[11px]">PRIORITY: HIGH / CRITICAL</span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-xs text-slate-500">Scanning incident ledger...</div>
        ) : events.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500">
            No unresolved security incidents detected in current window.
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {events.map((evt) => (
              <div key={evt.id} className="p-4 flex items-start justify-between gap-4 hover:bg-slate-800/30 transition-colors text-xs">
                <div className="flex items-start gap-3 min-w-0">
                  <div className="mt-0.5">
                    {evt.severity === 'CRITICAL' || evt.severity === 'HIGH' ? (
                      <AlertCircle className="w-4 h-4 text-rose-400" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-amber-400" />
                    )}
                  </div>
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-white font-mono">{evt.event_type}</span>
                      <span
                        className={`text-[10px] uppercase font-mono px-1.5 py-0.2 rounded ${
                          evt.severity === 'HIGH' || evt.severity === 'CRITICAL'
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : 'bg-amber-950 text-amber-300 border border-amber-800'
                        }`}
                      >
                        {evt.severity}
                      </span>
                      <span className="text-slate-500">·</span>
                      <span className="text-slate-400 font-mono">Actor: {evt.actor_email}</span>
                    </div>
                    <p className="text-slate-300 leading-relaxed font-mono text-[11px]">{evt.details}</p>
                    <div className="text-[10px] text-slate-500 font-mono">
                      Timestamp: {new Date(evt.timestamp).toISOString()}
                    </div>
                  </div>
                </div>

                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 shrink-0">
                  {evt.resolved ? 'RESOLVED' : 'LOGGED'}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
