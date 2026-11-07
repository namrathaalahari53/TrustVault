import React from 'react';
import { useAuth } from '../context/AuthContext';
import { ShieldAlert, ArrowLeft, Home } from 'lucide-react';

export const AccessDeniedPage: React.FC = () => {
  const { user, navigateTo } = useAuth();

  return (
    <div className="min-h-[60vh] flex flex-col items-center justify-center text-center p-6">
      <div className="w-14 h-14 rounded-2xl bg-rose-950/60 border border-rose-800/80 flex items-center justify-center text-rose-400 mb-4 shadow-xl">
        <ShieldAlert className="w-8 h-8" />
      </div>

      <h1 className="text-2xl font-bold text-white tracking-tight">403 — Access Denied</h1>
      <p className="mt-2 text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
        Zero-trust authorization policy rejected this request. You do not possess the required document permissions or administrative privileges. This denial has been recorded in the cryptographic audit trail.
      </p>

      <div className="mt-6 p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-400 max-w-md w-full">
        <div>Actor: <span className="text-white">{user?.email || 'Anonymous'}</span></div>
        <div className="mt-1">Policy: <span className="text-rose-400">STRICT_ZERO_TRUST_DENIAL</span></div>
      </div>

      <div className="mt-6 flex items-center gap-3">
        <button
          onClick={() => navigateTo('repository')}
          className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-md text-xs font-medium transition-colors"
        >
          <Home className="w-3.5 h-3.5" />
          <span>Return to Repository</span>
        </button>
      </div>
    </div>
  );
};
