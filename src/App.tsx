import React, { useState } from 'react';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { OfficerAuthProvider, useOfficerAuth } from './contexts/OfficerAuthContext';
import { AlertProvider } from './contexts/AlertContext';
import Navigation from './components/Navigation';
import Login from './components/Login';
import Signup from './components/Signup';
import Dashboard from './components/Dashboard';
import URLScanner from './components/URLScanner';
import QRScanner from './components/QRScanner';
import FileUpload from './components/FileUpload';
import ThreatMonitor from './components/ThreatMonitor';
import IncidentResponse from './components/IncidentResponse';
import VulnerabilityManagement from './components/VulnerabilityManagement';
import DataLossPrevention from './components/DataLossPrevention';
import ForensicsAudit from './components/ForensicsAudit';
import AIMLIntegration from './components/AIMLIntegration';
import About from './components/About';
import ReportBug from './components/ReportBug';
import OfficerLogin from './components/OfficerLogin';
import OfficerPanel from './components/OfficerPanel';
import LandingPage from './components/LandingPage';

// Router component to handle different routes
const Router: React.FC = () => {
  const [currentRoute, setCurrentRoute] = useState(window.location.pathname);
  const [userType, setUserType] = useState<'user' | 'officer' | null>(null);

  React.useEffect(() => {
    const handlePopState = () => {
      setCurrentRoute(window.location.pathname);
    };

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // NEW: Set userType based on route
  React.useEffect(() => {
    if (currentRoute.startsWith('/officer')) {
      setUserType('officer');
    } else if (currentRoute !== '/') {
      setUserType('user');
    } else {
      setUserType(null);
    }
  }, [currentRoute]);

  const navigate = (path: string) => {
    window.history.pushState({}, '', path);
    setCurrentRoute(path);
  };

  // If no user type is selected yet, show landing page
  if (!userType && currentRoute === '/') {
    return (
      <LandingPage onSelectUserType={(type) => {
        setUserType(type);
        navigate(type === 'officer' ? '/officer-login' : '/');
      }} />
    );
  }

  // Officer Panel route should come first!
  if (currentRoute === '/officer-panel') {
    return (
      <AlertProvider>
        <OfficerAuthProvider>
          <OfficerPanelPage onNavigate={navigate} />
        </OfficerAuthProvider>
      </AlertProvider>
    );
  }

  // Officer login route
  if (currentRoute === '/officer-login' || userType === 'officer') {
    return (
      <AlertProvider>
        <OfficerAuthProvider>
          <OfficerLoginPage onNavigate={navigate} />
        </OfficerAuthProvider>
      </AlertProvider>
    );
  }

  // Public user routes
  return (
    <AlertProvider>
      <AuthProvider>
        <PublicApp onNavigate={navigate} currentRoute={currentRoute} />
      </AuthProvider>
    </AlertProvider>
  );
};

// Officer Login Page Component
const OfficerLoginPage: React.FC<{ onNavigate: (path: string) => void }> = ({ onNavigate }) => {
  const { isAuthenticated, isInitialized } = useOfficerAuth();

  console.log('OfficerLoginPage - isAuthenticated:', isAuthenticated, 'isInitialized:', isInitialized);

  React.useEffect(() => {
    if (isInitialized && isAuthenticated) {
      console.log('Officer already authenticated, redirecting to panel');
      onNavigate('/officer-panel');
    }
  }, [isAuthenticated, isInitialized, onNavigate]);

  const handleLoginSuccess = () => {
    console.log('Login success callback triggered');
    // Small delay to ensure state is updated
    setTimeout(() => {
      console.log('Navigating to officer panel');
      onNavigate('/officer-panel');
    }, 100);
  };

  // Don't render anything while checking authentication
  if (!isInitialized) {
    return <div className="min-h-screen bg-cyber-darker flex items-center justify-center">
      <div className="cyber-loading"></div>
    </div>;
  }

  // If already authenticated, don't render the login page
  if (isAuthenticated) {
    return null;
  }

  return <OfficerLogin onLoginSuccess={handleLoginSuccess} />;
};

// Officer Panel Page Component
const OfficerPanelPage: React.FC<{ onNavigate: (path: string) => void }> = ({ onNavigate }) => {
  const { isAuthenticated, isInitialized } = useOfficerAuth();

  console.log('OfficerPanelPage - isAuthenticated:', isAuthenticated, 'isInitialized:', isInitialized);

  React.useEffect(() => {
    if (isInitialized && !isAuthenticated) {
      console.log('Officer not authenticated, redirecting to login');
      onNavigate('/officer-login');
    }
  }, [isAuthenticated, isInitialized, onNavigate]);

  // Don't render anything while checking authentication
  if (!isInitialized) {
    return <div className="min-h-screen bg-cyber-darker flex items-center justify-center">
      <div className="cyber-loading"></div>
    </div>;
  }

  // If not authenticated, don't render the panel
  if (!isAuthenticated) {
    return null;
  }

  return <OfficerPanel onNavigate={(page) => onNavigate(`/${page}`)} />;
};

// Public App Component
const PublicApp: React.FC<{ onNavigate: (path: string) => void; currentRoute: string }> = ({ onNavigate, currentRoute }) => {
  const { isAuthenticated } = useAuth();
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [isLogin, setIsLogin] = useState(true);

  // NEW: Sync currentPage with currentRoute
  React.useEffect(() => {
    const page = currentRoute.replace('/', '') || 'dashboard';
    setCurrentPage(page);
  }, [currentRoute]);

  const handleNavigation = (page: string) => {
    setCurrentPage(page);
    onNavigate(`/${page === 'dashboard' ? '' : page}`);
  };

  const toggleAuth = () => {
    setIsLogin(!isLogin);
  };

  if (!isAuthenticated) {
    return isLogin ? (
      <Login onToggleAuth={toggleAuth} />
    ) : (
      <Signup onToggleAuth={toggleAuth} />
    );
  }

  const renderCurrentPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard onNavigate={handleNavigation} />;
      case 'url-scanner':
        return <URLScanner onNavigate={handleNavigation} />;
      case 'qr-scanner':
        return <QRScanner onNavigate={handleNavigation} />;
      case 'file-upload':
        return <FileUpload onNavigate={handleNavigation} />;
      case 'threat-monitor':
        return <ThreatMonitor onNavigate={handleNavigation} />;
      case 'incident-response':
        return <IncidentResponse onNavigate={handleNavigation} />;
      case 'vulnerability-management':
        return <VulnerabilityManagement onNavigate={handleNavigation} />;
      case 'data-loss-prevention':
        return <DataLossPrevention onNavigate={handleNavigation} />;
      case 'forensics-audit':
        return <ForensicsAudit onNavigate={handleNavigation} />;
      case 'ai-ml-integration':
        return <AIMLIntegration onNavigate={handleNavigation} />;
      case 'report-bug':
        return <ReportBug onNavigate={handleNavigation} />;
      case 'about':
        return <About onNavigate={handleNavigation} />;
      default:
        return <Dashboard onNavigate={handleNavigation} />;
    }
  };

  return (
    <div className="min-h-screen bg-cyber-lighter">
      <Navigation currentPage={currentPage} onNavigate={handleNavigation} />
      <div className="p-4">
        {renderCurrentPage()}
      </div>
    </div>
  );
};

const App: React.FC = () => {
  return <Router />;
};

export default App;