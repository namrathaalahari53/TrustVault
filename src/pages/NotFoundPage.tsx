import React from 'react';
import { useAuth } from '../context/AuthContext';
import { FileQuestion, Home } from 'lucide-react';

export const NotFoundPage: React.FC = () => {
  const { navigateTo } = useAuth();

  return (
    <div className="min-h-[60vh] flex flex-col items-center justify-center text-center p-6">
      <div className="w-14 h-14 rounded-2xl bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-400 mb-4 shadow-xl">
        <FileQuestion className="w-8 h-8" />
      </div>

      <h1 className="text-2xl font-bold text-white tracking-tight">404 — Resource Not Found</h1>
      <p className="mt-2 text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
        The requested document, user record, or view does not exist in TrustVault or has been deleted.
      </p>

      <button
        onClick={() => navigateTo('repository')}
        className="mt-6 flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-md text-xs font-medium transition-colors"
      >
        <Home className="w-3.5 h-3.5" />
        <span>Return to Repository</span>
      </button>
    </div>
  );
};
