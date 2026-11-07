import React, { useState } from 'react';
import { useAuth, SEED_ACCOUNTS } from '../context/AuthContext';
import {
  Shield,
  Upload,
  User as UserIcon,
  LogOut,
  ChevronDown,
  CheckCircle,
  FileText,
  Activity,
  Settings,
  Lock,
} from 'lucide-react';

export const Navbar: React.FC = () => {
  const { user, isAdmin, isOwner, activeView, navigateTo, logout, quickLoginAs } = useAuth();
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showRoleSwitcher, setShowRoleSwitcher] = useState(false);

  return (
    <header className="sticky top-0 z-40 w-full bg-slate-950/95 backdrop-blur border-b border-slate-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between gap-8 h-16">
          {/* Zone 1: Single Brand Wordmark */}
          <button
            onClick={() => navigateTo('repository')}
            className="flex items-center gap-2.5 text-lg font-bold tracking-tight text-white whitespace-nowrap shrink-0 hover:opacity-90 transition-opacity"
          >
            <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-sm shadow-blue-500/20">
              <Shield className="w-4 h-4" />
            </div>
            <span>TrustVault</span>
          </button>

          {/* Zone 2: 4-5 Clean Single-Line Nav Links */}
          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400">
            <button
              onClick={() => navigateTo('repository')}
              className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
                activeView === 'repository' || activeView === 'document-detail' ? 'text-white font-semibold' : ''
              }`}
            >
              Repository
            </button>

            <button
              onClick={() => {
                if (isAdmin) navigateTo('admin-dashboard');
                else if (isOwner) navigateTo('owner-dashboard');
                else navigateTo('member-dashboard');
              }}
              className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
                activeView.includes('dashboard') ? 'text-white font-semibold' : ''
              }`}
            >
              Dashboard
            </button>

            <button
              onClick={() => navigateTo('audit-center')}
              className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
                activeView === 'audit-center' ? 'text-white font-semibold' : ''
              }`}
            >
              Audit Trail
            </button>

            <button
              onClick={() => navigateTo('security-tests')}
              className={`flex items-center gap-1.5 hover:text-white transition-colors whitespace-nowrap shrink-0 ${
                activeView === 'security-tests' ? 'text-blue-400 font-semibold' : ''
              }`}
            >
              <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
              <span>Security Tests (30/30)</span>
            </button>

            {isAdmin && (
              <button
                onClick={() => navigateTo('user-management')}
                className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
                  activeView === 'user-management' || activeView === 'security-events'
                    ? 'text-white font-semibold'
                    : ''
                }`}
              >
                Admin Console
              </button>
            )}
          </nav>

          {/* Zone 3: Primary Action + Fast Switcher + User Context */}
          <div className="flex items-center gap-3 shrink-0">
            {/* Quick Fast Switcher for Evaluating Roles */}
            <div className="relative">
              <button
                onClick={() => setShowRoleSwitcher(!showRoleSwitcher)}
                className="hidden lg:flex items-center gap-2 px-2.5 py-1.5 text-xs font-medium text-slate-300 bg-slate-900 border border-slate-700/80 rounded-md hover:border-slate-600 transition-colors whitespace-nowrap"
                title="Switch test persona instantly"
              >
                <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                <span className="text-slate-400">Role:</span>
                <span className="font-semibold text-white">{user?.role || 'Switch'}</span>
                <ChevronDown className="w-3 h-3 text-slate-400" />
              </button>

              {showRoleSwitcher && (
                <div className="absolute right-0 mt-2 w-72 bg-slate-900 border border-slate-800 rounded-lg shadow-xl py-2 z-50 text-xs">
                  <div className="px-3 py-1.5 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
                    Switch Test Account Persona
                  </div>
                  <div className="max-h-72 overflow-y-auto">
                    {SEED_ACCOUNTS.map((acc) => (
                      <button
                        key={acc.email}
                        onClick={() => {
                          quickLoginAs(acc.email, acc.pass);
                          setShowRoleSwitcher(false);
                        }}
                        className={`w-full text-left px-3 py-2 flex items-center justify-between hover:bg-slate-800/80 transition-colors ${
                          user?.email === acc.email ? 'bg-slate-800 text-blue-400' : 'text-slate-300'
                        }`}
                      >
                        <div>
                          <div className="font-medium text-white">{acc.label}</div>
                          <div className="text-[11px] text-slate-500 font-mono">{acc.email}</div>
                        </div>
                        <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                          {acc.role}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Upload Button */}
            {(isOwner || isAdmin) && (
              <button
                onClick={() => navigateTo('upload')}
                className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-white bg-blue-600 rounded-md hover:bg-blue-500 transition-colors whitespace-nowrap shadow-sm shadow-blue-600/30"
              >
                <Upload className="w-3.5 h-3.5" />
                <span>Upload</span>
              </button>
            )}

            {/* User Dropdown */}
            {user ? (
              <div className="relative">
                <button
                  onClick={() => setShowUserMenu(!showUserMenu)}
                  className="flex items-center gap-2 p-1.5 rounded-md hover:bg-slate-900 text-slate-300 transition-colors"
                >
                  <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-semibold text-slate-200">
                    {user.full_name.charAt(0)}
                  </div>
                  <span className="hidden sm:inline text-xs font-medium text-slate-200 max-w-[120px] truncate">
                    {user.full_name.split(' ')[0]}
                  </span>
                  <ChevronDown className="w-3 h-3 text-slate-400" />
                </button>

                {showUserMenu && (
                  <div className="absolute right-0 mt-2 w-64 bg-slate-900 border border-slate-800 rounded-lg shadow-2xl py-1 z-50 text-xs">
                    <div className="px-4 py-2.5 border-b border-slate-800">
                      <div className="font-semibold text-white truncate">{user.full_name}</div>
                      <div className="text-[11px] text-slate-400 font-mono truncate">{user.email}</div>
                      <div className="mt-1 flex items-center gap-1.5 text-[11px] text-slate-400">
                        <span>Role:</span>
                        <span className="font-semibold text-blue-400 font-mono">{user.role}</span>
                        <span>·</span>
                        <span className="truncate">{user.department}</span>
                      </div>
                    </div>

                    <button
                      onClick={() => {
                        navigateTo('profile');
                        setShowUserMenu(false);
                      }}
                      className="w-full text-left px-4 py-2 text-slate-300 hover:bg-slate-800 flex items-center gap-2"
                    >
                      <UserIcon className="w-3.5 h-3.5 text-slate-400" />
                      <span>Profile & Security Settings</span>
                    </button>

                    <button
                      onClick={() => {
                        navigateTo('first-time-password');
                        setShowUserMenu(false);
                      }}
                      className="w-full text-left px-4 py-2 text-slate-300 hover:bg-slate-800 flex items-center gap-2"
                    >
                      <Lock className="w-3.5 h-3.5 text-slate-400" />
                      <span>Change Password</span>
                    </button>

                    <div className="border-t border-slate-800 my-1"></div>

                    <button
                      onClick={() => {
                        logout();
                        setShowUserMenu(false);
                      }}
                      className="w-full text-left px-4 py-2 text-rose-400 hover:bg-slate-800 flex items-center gap-2"
                    >
                      <LogOut className="w-3.5 h-3.5" />
                      <span>Sign Out</span>
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <button
                onClick={() => navigateTo('login')}
                className="px-3.5 py-1.5 text-xs font-medium text-white bg-blue-600 rounded-md hover:bg-blue-500 transition-colors whitespace-nowrap"
              >
                Sign In
              </button>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
