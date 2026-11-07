import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import { User, UserRole } from '../types';
import {
  Users,
  UserPlus,
  Shield,
  CheckCircle,
  XCircle,
  KeyRound,
  RotateCcw,
  AlertCircle,
  Plus,
  X,
} from 'lucide-react';

export const UserManagementPage: React.FC = () => {
  const { user: currentAdmin, showToast } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  // New User Modal State
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newEmail, setNewEmail] = useState('');
  const [newName, setNewName] = useState('');
  const [newDept, setNewDept] = useState('Security Operations');
  const [newRole, setNewRole] = useState<UserRole>('VIEWER');
  const [isCreating, setIsCreating] = useState(false);
  const [createdTempPass, setCreatedTempPass] = useState<string | null>(null);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const res = await api.listUsers();
      setUsers(res.users);
    } catch (err: any) {
      showToast('error', 'Failed to load users', err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleToggleActive = async (targetUser: User) => {
    const action = targetUser.is_active ? 'deactivate' : 'reactivate';
    if (!window.confirm(`Are you sure you want to ${action} ${targetUser.email}?`)) {
      return;
    }

    try {
      await api.updateUser(targetUser.id, { is_active: !targetUser.is_active });
      showToast('success', 'User Status Updated', `Account ${targetUser.email} has been ${action}d.`);
      fetchUsers();
    } catch (err: any) {
      showToast('error', 'Status Update Denied', err.message);
    }
  };

  const handleRoleChange = async (targetUser: User, newRole: UserRole) => {
    try {
      await api.updateUser(targetUser.id, { role: newRole });
      showToast('success', 'Role Updated', `Updated role to ${newRole} for ${targetUser.email}`);
      fetchUsers();
    } catch (err: any) {
      showToast('error', 'Role Change Failed', err.message);
    }
  };

  const handleResetPassword = async (targetUser: User) => {
    if (!window.confirm(`Reset temporary password for ${targetUser.email}?`)) return;
    try {
      const res = await api.updateUser(targetUser.id, { reset_password: true });
      if (res.temporaryPassword) {
        alert(`New Temporary Password for ${targetUser.email}:\n\n${res.temporaryPassword}\n\nThe user must change it upon their next sign-in.`);
      }
      showToast('success', 'Password Reset', `Temporary password generated for ${targetUser.email}`);
      fetchUsers();
    } catch (err: any) {
      showToast('error', 'Reset Denied', err.message);
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsCreating(true);
    try {
      const res = await api.createUser({
        email: newEmail.trim(),
        full_name: newName.trim(),
        department: newDept.trim(),
        role: newRole,
      });

      setCreatedTempPass(res.temporaryPassword || 'Generated');
      showToast('success', 'User Created', `Provisioned account for ${res.user.email}`);
      fetchUsers();
    } catch (err: any) {
      showToast('error', 'Creation Failed', err.message);
    } finally {
      setIsCreating(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Identity & User Governance</h1>
          <p className="text-xs text-slate-400 mt-1">
            Provision managed identities, configure RBAC roles, deactivate compromised accounts, and issue temporary credentials.
          </p>
        </div>

        <button
          onClick={() => {
            setCreatedTempPass(null);
            setShowCreateModal(true);
          }}
          className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-blue-600 rounded-md hover:bg-blue-500 transition-colors shadow-sm self-start sm:self-auto"
        >
          <UserPlus className="w-3.5 h-3.5" />
          <span>Provision New Account</span>
        </button>
      </div>

      {/* Users Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between text-xs">
          <span className="font-semibold text-white">Registered System Accounts ({users.length})</span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-xs text-slate-500">Querying directory...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 font-mono text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-4">User</th>
                  <th className="py-2.5 px-3">Department</th>
                  <th className="py-2.5 px-3">Role</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">First-Time Rotation</th>
                  <th className="py-2.5 px-3 text-right">Administrative Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 font-mono text-[11px]">
                {users.map((u) => {
                  const isCurrent = u.id === currentAdmin?.id;
                  return (
                    <tr key={u.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4">
                        <div className="font-medium text-white font-sans">{u.full_name}</div>
                        <div className="text-[11px] text-slate-400 font-mono">{u.email}</div>
                      </td>
                      <td className="py-3 px-3 text-slate-300 font-sans">{u.department}</td>
                      <td className="py-3 px-3">
                        <select
                          value={u.role}
                          disabled={isCurrent}
                          onChange={(e) => handleRoleChange(u, e.target.value as UserRole)}
                          className="px-2 py-1 bg-slate-950 border border-slate-700 rounded text-[11px] text-white focus:outline-none focus:border-blue-500 disabled:opacity-50"
                        >
                          <option value="VIEWER">VIEWER</option>
                          <option value="OWNER">OWNER</option>
                          <option value="ADMIN">ADMIN</option>
                        </select>
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-mono ${
                            u.is_active
                              ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/60'
                              : 'bg-rose-950/80 text-rose-400 border border-rose-800/60'
                          }`}
                        >
                          {u.is_active ? 'ACTIVE' : 'DEACTIVATED'}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-400">
                        {u.must_change_password ? (
                          <span className="text-amber-400 font-medium">PENDING FIRST LOGIN</span>
                        ) : (
                          <span className="text-slate-500">ROTATED</span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-right space-x-2">
                        <button
                          onClick={() => handleResetPassword(u)}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] transition-colors"
                          title="Generate New Temporary Password"
                        >
                          Reset Pass
                        </button>
                        {!isCurrent && (
                          <button
                            onClick={() => handleToggleActive(u)}
                            className={`px-2 py-1 rounded text-[11px] transition-colors ${
                              u.is_active
                                ? 'bg-rose-950/60 border border-rose-800 text-rose-300 hover:bg-rose-900'
                                : 'bg-emerald-950/60 border border-emerald-800 text-emerald-300 hover:bg-emerald-900'
                            }`}
                          >
                            {u.is_active ? 'Deactivate' : 'Reactivate'}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Provision Account Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <h3 className="text-sm font-semibold text-white">Provision Member Account</h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {createdTempPass ? (
              <div className="p-4 bg-emerald-950/40 border border-emerald-800/80 rounded-lg text-xs space-y-2">
                <div className="font-semibold text-emerald-300 flex items-center gap-1.5">
                  <CheckCircle className="w-4 h-4 text-emerald-400" />
                  <span>Account Provisioned Successfully!</span>
                </div>
                <p className="text-slate-300">
                  Share these credentials securely with the employee. The user is required to rotate this password on first login.
                </p>
                <div className="p-2.5 bg-slate-950 rounded border border-slate-800 font-mono text-white text-xs select-all">
                  Temp Password: <span className="text-amber-400 font-bold">{createdTempPass}</span>
                </div>
                <button
                  onClick={() => setShowCreateModal(false)}
                  className="w-full mt-2 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded text-xs transition-colors"
                >
                  Done
                </button>
              </div>
            ) : (
              <form onSubmit={handleCreateUser} className="space-y-3 text-xs">
                <div>
                  <label className="block text-slate-300 mb-1">Full Name</label>
                  <input
                    type="text"
                    required
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    placeholder="e.g. Rachel Adams"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-white focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 mb-1">Corporate Email</label>
                  <input
                    type="email"
                    required
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                    placeholder="e.g. rachel@trustvault.security"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-white focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 mb-1">Department</label>
                  <input
                    type="text"
                    value={newDept}
                    onChange={(e) => setNewDept(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-white focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 mb-1">Initial RBAC Role</label>
                  <select
                    value={newRole}
                    onChange={(e) => setNewRole(e.target.value as UserRole)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="VIEWER">VIEWER / MEMBER (Read-only default)</option>
                    <option value="OWNER">OWNER (Upload & Delegate)</option>
                    <option value="ADMIN">ADMIN (Full SecOps Console)</option>
                  </select>
                </div>

                <div className="pt-2 flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setShowCreateModal(false)}
                    className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isCreating}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded font-medium transition-colors"
                  >
                    {isCreating ? 'Provisioning...' : 'Provision Account'}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
