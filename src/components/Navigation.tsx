import React, { useState } from 'react';
import {
  Shield, Home, Link, Upload, Info, User, Bug, QrCode, Activity,
  AlertTriangle, Target, Database, Search, Brain, ChevronDown, Menu, X
} from 'lucide-react';

import { useAuth } from '../contexts/AuthContext';
import { NavigationProps } from '../types';
import AlertBadge from './AlertBadge';
import AlertPanel from './AlertPanel';
import UserProfile from './UserProfile';

const Navigation: React.FC<NavigationProps> = ({ currentPage, onNavigate }) => {
  const { user } = useAuth();
  const [alertPanelOpen, setAlertPanelOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);

  const coreFeatures = [
    { id: 'url-scanner', label: 'URL Scanner', icon: Link, description: 'Analyze suspicious links' },
    { id: 'qr-scanner', label: 'QR Scanner', icon: QrCode, description: 'Check QR codes for threats' },
    { id: 'file-upload', label: 'File Analyzer', icon: Upload, description: 'Scan files for malware' }
  ];

  const advancedFeatures = [
    { id: 'threat-monitor', label: 'Threat Intelligence', icon: Activity, description: 'Real-time threat monitoring' },
    { id: 'incident-response', label: 'Incident Response', icon: AlertTriangle, description: 'Automated incident handling' },
    { id: 'vulnerability-management', label: 'Vulnerability Management', icon: Target, description: 'Scan and patch vulnerabilities' },
    { id: 'data-loss-prevention', label: 'Data Loss Prevention', icon: Database, description: 'Monitor data transfers' },
    { id: 'forensics-audit', label: 'Digital Forensics', icon: Search, description: 'Evidence and audit trails' },
    { id: 'ai-ml-integration', label: 'AI/ML Analytics', icon: Brain, description: 'Behavioral analytics' }
  ];

  const utilityFeatures = [
    { id: 'report-bug', label: 'Report Bug', icon: Bug, description: 'Report security issues' },
    { id: 'about', label: 'About', icon: Info, description: 'Learn about CyberIntel' }
  ];

  const allFeatures = [...coreFeatures, ...advancedFeatures, ...utilityFeatures];
  const isFeatureSelected = allFeatures.some((f) => f.id === currentPage);

  const handleFeatureClick = (id: string) => {
    onNavigate(id);
    setDropdownOpen(false);
    setMobileMenuOpen(false);
  };

  return (
    <>
      <nav className="bg-black/95 backdrop-blur-md border-b border-cyber-primary/20 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-3">
              <div className="relative">
                <Shield className="w-8 h-8 text-cyber-primary" />
                <div className="absolute inset-0 animate-cyber-pulse">
                  <Shield className="w-8 h-8 text-cyber-primary/50" />
                </div>
              </div>
              <span className="text-xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyber-primary to-cyber-accent font-cyber">
                CYBERINTEL
              </span>
            </div>

            {/* Desktop Navigation */}
            <div className="hidden lg:flex items-center space-x-6">
              {/* Dashboard */}
              <button
                onClick={() => onNavigate('/dashboard')}
                className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                  currentPage === 'dashboard'
                    ? 'bg-cyber-primary/20 text-cyber-primary shadow-lg shadow-cyber-primary/25 cyber-button'
                    : 'text-gray-300 hover:text-cyber-primary hover:bg-cyber-primary/10'
                }`}
              >
                <Home className="w-4 h-4" />
                <span className="font-cyber">DASHBOARD</span>
              </button>

              <div className={`relative hacker-dropdown ${dropdownOpen ? 'open' : ''}`}>
                <button
                  onClick={() => setDropdownOpen(!dropdownOpen)}
                  className={`hacker-dropdown-toggle ${
                    isFeatureSelected ? 'bg-cyber-primary/20 text-cyber-primary shadow-lg shadow-cyber-primary/25 cyber-button' : ''
                  }`}
                >
                  <Shield className="w-4 h-4" />
                  <span className="font-cyber">SECURITY TOOLS</span>
                  <ChevronDown className={`w-4 h-4 transition-transform duration-200 ${dropdownOpen ? 'rotate-180' : ''}`} />
                </button>

                {dropdownOpen && (
                  <div className="hacker-dropdown-menu">
                    <Section title="Core Security" color="text-cyber-primary" features={coreFeatures} currentPage={currentPage} onNavigate={handleFeatureClick} />
                    <div className="hacker-dropdown-divider"></div>
                    <Section title="Advanced Operations" color="text-cyber-accent" features={advancedFeatures} currentPage={currentPage} onNavigate={handleFeatureClick} />
                    <div className="hacker-dropdown-divider"></div>
                    <Section title="Support & Info" color="text-blue-400" features={utilityFeatures} currentPage={currentPage} onNavigate={handleFeatureClick} />
                  </div>
                )}
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <AlertBadge onClick={() => setAlertPanelOpen(true)} />
              <button
                onClick={() => setProfileOpen(true)}
                className="cyber-button flex items-center space-x-2 px-3 py-2 rounded-lg text-cyber-primary hover:text-white hover:bg-cyber-primary/20 transition-all duration-200"
              >
                <User className="w-4 h-4" />
                <span className="hidden sm:inline text-sm font-cyber">{user?.fullName}</span>
              </button>
              <button
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className="lg:hidden p-2 text-gray-400 hover:text-cyber-primary transition-colors"
              >
                {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
              </button>
            </div>
          </div>

          {mobileMenuOpen && (
            <div className="lg:hidden pb-4 border-t border-cyber-primary/30 mt-4 pt-4 space-y-4">
              {[{ title: 'Core Security', color: 'text-cyber-primary', features: coreFeatures },
                { title: 'Advanced Operations', color: 'text-cyber-accent', features: advancedFeatures },
                { title: 'Support & Info', color: 'text-blue-400', features: utilityFeatures }].map((section) => (
                <div key={section.title}>
                  <h3 className={`text-xs font-semibold ${section.color} uppercase tracking-wider mb-2 px-4 font-cyber`}>{section.title}</h3>
                  {section.features.map((feature: any) => {
                    const Icon = feature.icon;
                    return (
                      <button
                        key={feature.id}
                        onClick={() => handleFeatureClick(feature.id)}
                        className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-left transition-all duration-200 ${
                          currentPage === feature.id
                            ? `${section.color.replace('text-', 'bg-')}/20 ${section.color}`
                            : 'text-gray-300 hover:text-white hover:bg-gray-700/50'
                        }`}
                      >
                        <Icon className="w-5 h-5" />
                        <div>
                          <div className="font-medium font-cyber">{feature.label}</div>
                          <div className="text-xs text-gray-400">{feature.description}</div>
                        </div>
                      </button>
                    );
                  })}
                </div>
              ))}
            </div>
          )}
        </div>

        {dropdownOpen && (
          <div
            className="fixed inset-0 z-40"
            onClick={() => setDropdownOpen(false)}
          />
        )}
      </nav>

      <AlertPanel isOpen={alertPanelOpen} onClose={() => setAlertPanelOpen(false)} />
      <UserProfile isOpen={profileOpen} onClose={() => setProfileOpen(false)} />
    </>
  );
};

const Section = ({ title, color, features, currentPage, onNavigate }: any) => (
  <div className="mb-4">
    <h3 className={`text-xs font-semibold uppercase tracking-wider mb-3 font-cyber ${color}`}>
      {title}
    </h3>
    <div className="space-y-1">
      {features.map((feature: any) => {
        const Icon = feature.icon;
        return (
          <button
            key={feature.id}
            onClick={() => onNavigate(feature.id)}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-left transition-all duration-200 ${
              currentPage === feature.id
                ? `${color.replace('text-', 'bg-')}/20 ${color}`
                : 'text-gray-300 hover:text-white hover:bg-gray-700/50'
            }`}
          >
            <Icon className="w-4 h-4 flex-shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium font-cyber">{feature.label}</div>
              <div className="text-xs text-gray-400 truncate">{feature.description}</div>
            </div>
          </button>
        );
      })}
    </div>
  </div>
);

export default Navigation;
