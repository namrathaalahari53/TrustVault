import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { User, UserRole } from '../types';
import { api } from '../services/api';

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  title: string;
  message: string;
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  isAdmin: boolean;
  isOwner: boolean;
  isViewer: boolean;
  activeView: string;
  selectedDocId: string | null;
  toasts: ToastMessage[];
  login: (email: string, pass: string) => Promise<User>;
  register: (payload: {
    email: string;
    password: string;
    full_name: string;
    department?: string;
    role?: 'OWNER' | 'VIEWER';
  }) => Promise<User>;
  quickLoginAs: (email: string, pass: string) => Promise<void>;
  logout: () => Promise<void>;
  navigateTo: (view: string, docId?: string) => void;
  showToast: (type: ToastMessage['type'], title: string, message: string) => void;
  dismissToast: (id: string) => void;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const SEED_ACCOUNTS = [
  { label: 'Admin (Arthur Vance)', email: 'admin@trustvault.security', pass: 'AdminPassword123!', role: 'ADMIN' },
  { label: 'Owner A (Alex Rivera)', email: 'owner_alex@trustvault.security', pass: 'OwnerPassword123!', role: 'OWNER' },
  { label: 'Owner B (Elena Rostova)', email: 'owner_elena@trustvault.security', pass: 'OwnerPassword123!', role: 'OWNER' },
  { label: 'Viewer (Sarah Chen - READ)', email: 'viewer_sarah@trustvault.security', pass: 'ViewerPassword123!', role: 'VIEWER' },
  { label: 'Editor (David Keller - EDIT)', email: 'editor_david@trustvault.security', pass: 'EditorPassword123!', role: 'VIEWER' },
  { label: 'Unauthorized (John Miller)', email: 'unauth_john@trustvault.security', pass: 'JohnPassword123!', role: 'VIEWER' },
  { label: 'First-Login (Taylor Quinn)', email: 'temp_user@trustvault.security', pass: 'TempPassword123!', role: 'VIEWER' },
  { label: 'Inactive (Mark Hansen)', email: 'inactive_mark@trustvault.security', pass: 'InactivePassword123!', role: 'VIEWER' },
];

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [activeView, setActiveView] = useState<string>('repository');
  const [selectedDocId, setSelectedDocId] = useState<string | null>(null);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const showToast = (type: ToastMessage['type'], title: string, message: string) => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts((prev) => [...prev, { id, type, title, message }]);
    setTimeout(() => {
      dismissToast(id);
    }, 5000);
  };

  const dismissToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const refreshUser = async () => {
    try {
      if (api.getToken()) {
        const u = await api.getMe();
        setUser(u);
      } else {
        setUser(null);
      }
    } catch {
      api.clearToken();
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshUser();
  }, []);

  const login = async (email: string, pass: string): Promise<User> => {
    setLoading(true);
    try {
      const { user: loggedInUser } = await api.login(email, pass);
      setUser(loggedInUser);

      if (loggedInUser.must_change_password) {
        setActiveView('first-time-password');
      } else if (loggedInUser.role === 'ADMIN') {
        setActiveView('admin-dashboard');
      } else if (loggedInUser.role === 'OWNER') {
        setActiveView('owner-dashboard');
      } else {
        setActiveView('member-dashboard');
      }

      showToast('success', 'Authenticated', `Welcome back, ${loggedInUser.full_name}`);
      return loggedInUser;
    } catch (err: any) {
      showToast('error', 'Login Failed', err.message || 'Authentication failed');
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const register = async (payload: {
    email: string;
    password: string;
    full_name: string;
    department?: string;
    role?: 'OWNER' | 'VIEWER';
  }): Promise<User> => {
    setLoading(true);
    try {
      const { user: registeredUser } = await api.register(payload);
      setUser(registeredUser);

      if (registeredUser.role === 'OWNER') {
        setActiveView('owner-dashboard');
      } else {
        setActiveView('member-dashboard');
      }

      showToast('success', 'Account Created', `Welcome to TrustVault, ${registeredUser.full_name}`);
      return registeredUser;
    } catch (err: any) {
      showToast('error', 'Registration Failed', err.message || 'Could not create account');
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const quickLoginAs = async (email: string, pass: string) => {
    await login(email, pass);
  };

  const logout = async () => {
    try {
      await api.logout();
    } catch {}
    setUser(null);
    setActiveView('login');
    showToast('info', 'Logged Out', 'Your secure session has been terminated.');
  };

  const navigateTo = (view: string, docId?: string) => {
    if (docId) setSelectedDocId(docId);
    setActiveView(view);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const isAdmin = user?.role === 'ADMIN';
  const isOwner = user?.role === 'OWNER';
  const isViewer = user?.role === 'VIEWER';

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        isAdmin,
        isOwner,
        isViewer,
        activeView,
        selectedDocId,
        toasts,
        login,
        register,
        quickLoginAs,
        logout,
        navigateTo,
        showToast,
        dismissToast,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
