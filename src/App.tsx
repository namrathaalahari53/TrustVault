import React from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { ToastContainer } from './components/ToastContainer';

// Pages
import { LoginPage } from './pages/LoginPage';
import { FirstTimePasswordChangePage } from './pages/FirstTimePasswordChangePage';
import { AdminDashboardPage } from './pages/AdminDashboardPage';
import { OwnerDashboardPage } from './pages/OwnerDashboardPage';
import { MemberDashboardPage } from './pages/MemberDashboardPage';
import { RepositoryPage } from './pages/RepositoryPage';
import { DocumentDetailPage } from './pages/DocumentDetailPage';
import { UploadPage } from './pages/UploadPage';
import { AccessManagementPage } from './pages/AccessManagementPage';
import { AuditCenterPage } from './pages/AuditCenterPage';
import { UserManagementPage } from './pages/UserManagementPage';
import { SecurityEventsPage } from './pages/SecurityEventsPage';
import { ProfilePage } from './pages/ProfilePage';
import { AccessDeniedPage } from './pages/AccessDeniedPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { SecurityTestsPage } from './pages/SecurityTestsPage';

const AppContent: React.FC = () => {
  const { user, loading, activeView } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-xs text-slate-500">
        <div className="w-8 h-8 rounded-full border-2 border-blue-500 border-t-transparent animate-spin mb-3"></div>
        <div className="font-mono">Establishing secure TrustVault session...</div>
      </div>
    );
  }

  // If not logged in and not on a public view, show Login
  if (!user && activeView !== 'login') {
    return (
      <>
        <LoginPage />
        <ToastContainer />
      </>
    );
  }

  const renderActiveView = () => {
    switch (activeView) {
      case 'login':
        return <LoginPage />;
      case 'first-time-password':
        return <FirstTimePasswordChangePage />;
      case 'admin-dashboard':
        return <AdminDashboardPage />;
      case 'owner-dashboard':
        return <OwnerDashboardPage />;
      case 'member-dashboard':
        return <MemberDashboardPage />;
      case 'repository':
        return <RepositoryPage />;
      case 'document-detail':
        return <DocumentDetailPage />;
      case 'upload':
        return <UploadPage />;
      case 'access-management':
        return <AccessManagementPage />;
      case 'audit-center':
        return <AuditCenterPage />;
      case 'user-management':
        return <UserManagementPage />;
      case 'security-events':
        return <SecurityEventsPage />;
      case 'profile':
        return <ProfilePage />;
      case 'access-denied':
        return <AccessDeniedPage />;
      case 'security-tests':
        return <SecurityTestsPage />;
      default:
        return <NotFoundPage />;
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
      <Navbar />

      <div className="flex-1 flex overflow-hidden max-w-7xl w-full mx-auto">
        <Sidebar />
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8">
          {renderActiveView()}
        </main>
      </div>

      <ToastContainer />
    </div>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
