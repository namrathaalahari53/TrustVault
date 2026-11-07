import React from 'react';
import { useAuth } from '../context/AuthContext';
import {
  FolderLock,
  Upload,
  LayoutDashboard,
  ShieldAlert,
  Users,
  ScrollText,
  KeyRound,
  FileCheck2,
  Lock,
  ShieldCheck,
  CheckCircle2,
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const { user, isAdmin, isOwner, activeView, navigateTo } = useAuth();

  const links = [
    {
      id: 'repository',
      label: 'Secure Repository',
      icon: FolderLock,
      show: true,
    },
    {
      id: 'upload',
      label: 'Upload Document',
      icon: Upload,
      show: isOwner || isAdmin,
    },
    {
      id: 'owner-dashboard',
      label: 'Owner Dashboard',
      icon: LayoutDashboard,
      show: isOwner || isAdmin,
    },
    {
      id: 'member-dashboard',
      label: 'Member Dashboard',
      icon: LayoutDashboard,
      show: !isOwner && !isAdmin,
    },
    {
      id: 'access-management',
      label: 'Access Management',
      icon: KeyRound,
      show: isOwner || isAdmin,
    },
    {
      id: 'audit-center',
      label: 'Audit Trail Center',
      icon: ScrollText,
      show: true,
    },
    {
      id: 'security-tests',
      label: 'Security Test Suite',
      icon: ShieldCheck,
      show: true,
      badge: '30/30',
    },
    // Admin only
    {
      id: 'admin-dashboard',
      label: 'Admin Overview',
      icon: LayoutDashboard,
      show: isAdmin,
    },
    {
      id: 'user-management',
      label: 'User Management',
      icon: Users,
      show: isAdmin,
    },
    {
      id: 'security-events',
      label: 'Security Incident Log',
      icon: ShieldAlert,
      show: isAdmin,
    },
    {
      id: 'profile',
      label: 'Account & Security',
      icon: Lock,
      show: true,
    },
  ];

  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-800 p-4 shrink-0 hidden md:flex flex-col justify-between">
      <div className="space-y-6">
        <div>
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider px-3 mb-2 font-mono">
            Navigation
          </div>
          <div className="space-y-1">
            {links
              .filter((l) => l.show)
              .map((link) => {
                const Icon = link.icon;
                const isActive = activeView === link.id;
                return (
                  <button
                    key={link.id}
                    onClick={() => navigateTo(link.id)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition-colors ${
                      isActive
                        ? 'bg-blue-600/10 text-blue-400 border border-blue-500/20'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <Icon className={`w-4 h-4 ${isActive ? 'text-blue-400' : 'text-slate-500'}`} />
                      <span>{link.label}</span>
                    </div>
                    {link.badge && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        {link.badge}
                      </span>
                    )}
                  </button>
                );
              })}
          </div>
        </div>

        <div className="pt-4 border-t border-slate-800/80">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider px-3 mb-2 font-mono">
            Security Status
          </div>
          <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3 text-xs space-y-2">
            <div className="flex items-center justify-between text-slate-300">
              <span className="text-slate-400">Cryptographic Chain</span>
              <span className="flex items-center gap-1 text-emerald-400 font-medium">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Verified</span>
              </span>
            </div>
            <div className="flex items-center justify-between text-slate-300">
              <span className="text-slate-400">Zero-Trust Guard</span>
              <span className="text-blue-400 font-mono">ACTIVE</span>
            </div>
            <div className="flex items-center justify-between text-slate-300">
              <span className="text-slate-400">Revocation</span>
              <span className="text-amber-400 font-mono">IMMEDIATE</span>
            </div>
          </div>
        </div>
      </div>

      {user && (
        <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 text-xs">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-emerald-400"></div>
            <span className="text-slate-400">Authenticated:</span>
          </div>
          <div className="mt-1 font-mono text-[11px] text-slate-300 truncate">{user.email}</div>
          <div className="text-[10px] text-slate-500 font-mono mt-0.5 uppercase">ROLE: {user.role}</div>
        </div>
      )}
    </aside>
  );
};
