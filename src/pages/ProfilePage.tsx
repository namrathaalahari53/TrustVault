import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import { User, Lock, KeyRound, Shield, CheckCircle, AlertCircle } from 'lucide-react';

export const ProfilePage: React.FC = () => {
  const { user, showToast } = useAuth();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isUpdating, setIsUpdating] = useState(false);
  const [statusMsg, setStatusMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatusMsg(null);

    if (newPassword !== confirmPassword) {
      setStatusMsg({ type: 'error', text: 'New passwords do not match.' });
      return;
    }

    if (newPassword.length < 10) {
      setStatusMsg({ type: 'error', text: 'Password must be at least 10 characters long.' });
      return;
    }

    setIsUpdating(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      setStatusMsg({ type: 'success', text: 'Your password has been securely updated and audited.' });
      showToast('success', 'Password Updated', 'Your security credentials were rotated successfully.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: err.message || 'Failed to update password.' });
      showToast('error', 'Update Failed', err.message);
    } finally {
      setIsUpdating(false);
    }
  };

  if (!user) return null;

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div className="pb-4 border-b border-slate-800">
        <h1 className="text-xl font-bold text-white tracking-tight">Account & Security Credentials</h1>
        <p className="text-xs text-slate-400 mt-1">
          Review your cryptographic identity, role boundaries, and rotate account credentials.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* User Identity Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="w-12 h-12 rounded-full bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400 font-bold text-lg">
            {user.full_name.charAt(0)}
          </div>

          <div>
            <h2 className="text-sm font-bold text-white">{user.full_name}</h2>
            <div className="text-[11px] text-slate-400 font-mono">{user.email}</div>
          </div>

          <div className="pt-3 border-t border-slate-800 space-y-2 text-xs">
            <div>
              <span className="text-[11px] text-slate-500 block">User Identifier</span>
              <span className="font-mono text-slate-300 text-[11px]">{user.id}</span>
            </div>
            <div>
              <span className="text-[11px] text-slate-500 block">Assigned Role</span>
              <span className="font-mono text-blue-400 font-semibold">{user.role}</span>
            </div>
            <div>
              <span className="text-[11px] text-slate-500 block">Department</span>
              <span className="text-slate-300">{user.department}</span>
            </div>
            <div>
              <span className="text-[11px] text-slate-500 block">Account Status</span>
              <span className="text-emerald-400 font-mono font-medium">ACTIVE</span>
            </div>
          </div>
        </div>

        {/* Change Password Form */}
        <div className="md:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div>
            <h3 className="text-xs font-semibold text-white uppercase tracking-wider font-mono">
              Rotate Password
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Argon2/PBKDF2-SHA512 password hashing with individual salt.
            </p>
          </div>

          {statusMsg && (
            <div
              className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${
                statusMsg.type === 'success'
                  ? 'bg-emerald-950/60 border-emerald-800 text-emerald-200'
                  : 'bg-rose-950/60 border-rose-800 text-rose-200'
              }`}
            >
              {statusMsg.type === 'success' ? (
                <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              )}
              <span>{statusMsg.text}</span>
            </div>
          )}

          <form onSubmit={handlePasswordChange} className="space-y-3 text-xs">
            <div>
              <label className="block text-slate-300 mb-1">Current Password</label>
              <input
                type="password"
                required
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-white focus:outline-none focus:border-blue-500"
                placeholder="••••••••••••"
              />
            </div>

            <div>
              <label className="block text-slate-300 mb-1">New Secure Password</label>
              <input
                type="password"
                required
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-white focus:outline-none focus:border-blue-500"
                placeholder="At least 10 characters"
              />
            </div>

            <div>
              <label className="block text-slate-300 mb-1">Confirm New Password</label>
              <input
                type="password"
                required
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-white focus:outline-none focus:border-blue-500"
                placeholder="••••••••••••"
              />
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={isUpdating}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded font-medium transition-colors"
              >
                {isUpdating ? 'Updating...' : 'Update Password'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};
