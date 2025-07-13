import React, { useState, useEffect } from 'react';
import { Shield, Users, AlertTriangle, FileText, Download, CheckCircle, Clock, Filter, Search, Zap, X, Save, Eye, LogOut, Link, QrCode, Upload, Activity, Target, Database, Brain, ArrowRight, Terminal, Cpu, Server, HardDrive, Wifi, Network, Lock, Maximize, Minimize, BarChart, PieChart, Layers , Globe } from 'lucide-react';
import { useOfficerAuth } from '../contexts/OfficerAuthContext';
import { ScanResult, BugReport } from '../types';

interface OfficerPanelProps {
  onNavigate: (page: string) => void;
}

const OfficerPanel: React.FC<OfficerPanelProps> = ({ onNavigate }) => {
  const { officer, logout } = useOfficerAuth();
  const [activeTab, setActiveTab] = useState('dashboard');
  const [scanLogs, setScanLogs] = useState<ScanResult[]>([]);
  const [bugReports, setBugReports] = useState<BugReport[]>([]);
  const [filterRisk, setFilterRisk] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [scanLines, setScanLines] = useState<number[]>([]);
  const [floatingIcons, setFloatingIcons] = useState<{icon: any, x: number, y: number, size: number, speed: number, rotation: number}[]>([]);
  const [terminalLines, setTerminalLines] = useState<string[]>([]);
  const [terminalCursor, setTerminalCursor] = useState(true);
  const [maximized, setMaximized] = useState(false);
  
  // Modal states
  const [viewModalOpen, setViewModalOpen] = useState(false);
  const [notesModalOpen, setNotesModalOpen] = useState(false);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [selectedBug, setBugReport] = useState<BugReport | null>(null);
  const [officerNotes, setOfficerNotes] = useState('');

  // Generate cyberpunk visual effects
  useEffect(() => {
    // Generate scan lines
    const lines = [];
    for (let i = 0; i < 20; i++) {
      lines.push(Math.floor(Math.random() * 100));
    }
    setScanLines(lines);

    const interval = setInterval(() => {
      const newLines = [];
      for (let i = 0; i < 20; i++) {
        newLines.push(Math.floor(Math.random() * 100));
      }
      setScanLines(newLines);
    }, 3000);

    // Generate floating icons
    const icons = [Terminal, Cpu, Server, Database, HardDrive, Wifi, Network, Lock, Shield];
    const floatingElements = [];
    
    for (let i = 0; i < 15; i++) {
      floatingElements.push({
        icon: icons[Math.floor(Math.random() * icons.length)],
        x: Math.random() * 100,
        y: Math.random() * 100,
        size: 15 + Math.random() * 25,
        speed: 10 + Math.random() * 20,
        rotation: Math.random() * 360
      });
    }
    
    setFloatingIcons(floatingElements);

    // Terminal text animation
    const terminalMessages = [
      "INITIALIZING THREATOPS COMMAND CENTER...",
      "LOADING SECURITY MODULES...",
      "CONNECTING TO THREAT INTELLIGENCE FEEDS...",
      "ESTABLISHING SECURE CHANNEL...",
      "VERIFYING OFFICER CREDENTIALS...",
      "ACCESS GRANTED: WELCOME OFFICER",
      `OFFICER ID: ${officer?.officerId || 'UNKNOWN'}`,
      `DEPARTMENT: ${officer?.department || 'UNKNOWN'}`,
      "SECURITY CLEARANCE: LEVEL 5",
      "SYSTEM READY"
    ];
    
    let currentLine = 0;
    const terminalInterval = setInterval(() => {
      if (currentLine < terminalMessages.length) {
        setTerminalLines(prev => [...prev, terminalMessages[currentLine]]);
        currentLine++;
      } else {
        clearInterval(terminalInterval);
      }
    }, 500);
    
    const cursorInterval = setInterval(() => {
      setTerminalCursor(prev => !prev);
    }, 500);

    // Load mock data
    loadMockData();
    console.log("Officer Panel mounted, officer:", officer);

    return () => {
      clearInterval(interval);
      clearInterval(terminalInterval);
      clearInterval(cursorInterval);
    };
  }, [officer]);

  const loadMockData = () => {
    // Mock scan logs
    const mockScans: ScanResult[] = [
      {
        id: '1',
        type: 'url',
        target: 'https://suspicious-phishing.com/login',
        report: '🚫 DANGEROUS: Phishing attempt detected\n\nThis URL contains suspicious patterns commonly used in credential harvesting attacks. The domain mimics legitimate services but redirects to malicious servers designed to steal login credentials.\n\nRecommendation: Block this URL immediately and warn users about similar phishing attempts.',
        riskLevel: 'dangerous',
        timestamp: new Date(Date.now() - 1000 * 60 * 30),
        userEmail: 'john.doe@example.com',
        status: 'pending'
      },
      {
        id: '2',
        type: 'file',
        target: 'document.exe',
        report: '⚠️ SUSPICIOUS: Potential malware signatures\n\nFile analysis reveals suspicious executable patterns and obfuscated code sections. The file may contain trojans or backdoor access tools.\n\nRecommendation: Quarantine file and perform deep sandbox analysis before allowing execution.',
        riskLevel: 'suspicious',
        timestamp: new Date(Date.now() - 1000 * 60 * 60),
        userEmail: 'jane.smith@example.com',
        status: 'resolved',
        officerNotes: 'False positive - legitimate software installer verified through vendor signature'
      },
      {
        id: '3',
        type: 'url',
        target: 'https://example.com',
        report: '✅ SAFE: No threats detected\n\nURL analysis shows legitimate domain with proper SSL certificates and clean reputation. No suspicious patterns or malicious indicators found.\n\nRecommendation: Safe for normal browsing activities.',
        riskLevel: 'safe',
        timestamp: new Date(Date.now() - 1000 * 60 * 90),
        userEmail: 'alice.johnson@example.com',
        status: 'resolved'
      },
      {
        id: '4',
        type: 'file',
        target: 'ransomware.zip',
        report: '🚫 DANGEROUS: Ransomware detected\n\nFile analysis has identified signatures matching known ransomware variants. This file contains malicious code designed to encrypt user files and demand payment for decryption.\n\nRecommendation: Immediately quarantine and delete this file. Scan system for additional infections.',
        riskLevel: 'dangerous',
        timestamp: new Date(Date.now() - 1000 * 60 * 120),
        userEmail: 'robert.brown@example.com',
        status: 'pending'
      },
      {
        id: '5',
        type: 'url',
        target: 'https://malware-distribution.net/download',
        report: '🚫 DANGEROUS: Malware distribution site\n\nThis URL is associated with a known malware distribution network. Visiting this site may result in drive-by downloads of malicious software.\n\nRecommendation: Block this domain across the organization and investigate any systems that have accessed it.',
        riskLevel: 'dangerous',
        timestamp: new Date(Date.now() - 1000 * 60 * 150),
        userEmail: 'emma.wilson@example.com',
        status: 'pending'
      }
    ];

    // Mock bug reports
    const mockBugs: BugReport[] = [
      {
        id: '1',
        userId: '1',
        userEmail: 'user1@example.com',
        title: 'Scanner not detecting known malware',
        description: 'The URL scanner failed to identify a known phishing site that should have been flagged. I tested with a URL from the PhishTank database and it came back as safe when it should be dangerous.',
        url: 'https://known-phishing-site.com',
        timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2),
        status: 'open',
        aiSuggestion: 'Update threat intelligence database with latest phishing indicators from PhishTank and other threat feeds. Implement real-time reputation checking.'
      },
      {
        id: '2',
        userId: '2',
        userEmail: 'user2@example.com',
        title: 'File upload timeout error',
        description: 'Large files (>50MB) are timing out during analysis. The system shows a loading spinner but never completes the scan, eventually showing a timeout error.',
        timestamp: new Date(Date.now() - 1000 * 60 * 60 * 4),
        status: 'assigned',
        assignedOfficer: officer?.fullName,
        aiSuggestion: 'Implement chunked file processing for large files and increase timeout limits for complex analysis operations.'
      },
      {
        id: '3',
        userId: '3',
        userEmail: 'user3@example.com',
        title: 'False positive on legitimate banking site',
        description: 'The URL scanner is incorrectly flagging my legitimate banking website (chase.com) as suspicious. This is preventing me from accessing important financial information.',
        url: 'https://www.chase.com',
        timestamp: new Date(Date.now() - 1000 * 60 * 60 * 8),
        status: 'open',
        aiSuggestion: 'Review and update the URL classification algorithm to better recognize legitimate financial institutions. Consider implementing a whitelist for verified banking domains.'
      }
    ];

    setScanLogs(mockScans);
    setBugReports(mockBugs);
  };

  const handleViewScan = (scan: ScanResult) => {
    setSelectedScan(scan);
    setViewModalOpen(true);
  };

  const handleAddNotes = (scan: ScanResult) => {
    setSelectedScan(scan);
    setOfficerNotes(scan.officerNotes || '');
    setNotesModalOpen(true);
  };

  const handleSaveNotes = () => {
    if (selectedScan) {
      setScanLogs(prev => prev.map(scan => 
        scan.id === selectedScan.id ? { ...scan, officerNotes } : scan
      ));
      setNotesModalOpen(false);
      setOfficerNotes('');
      setSelectedScan(null);
    }
  };

  const handleMarkResolved = (scanId: string) => {
    setScanLogs(prev => prev.map(scan => 
      scan.id === scanId ? { ...scan, status: 'resolved' } : scan
    ));
  };

  const handleAssignBug = (bugId: string) => {
    setBugReports(prev => prev.map(bug => 
      bug.id === bugId ? { ...bug, status: 'assigned', assignedOfficer: officer?.fullName } : bug
    ));
  };

  const handleResolveBug = (bugId: string, resolution: string) => {
    setBugReports(prev => prev.map(bug => 
      bug.id === bugId ? { ...bug, status: 'resolved', resolution } : bug
    ));
  };

  const handleViewBug = (bug: BugReport) => {
    setBugReport(bug);
    setViewModalOpen(true);
  };

  const handleLogout = () => {
    logout();
    window.location.href = '/';
    window.location.reload();
  };

  const filteredScans = scanLogs.filter(scan => {
    const matchesRisk = filterRisk === 'all' || scan.riskLevel === filterRisk;
    const matchesSearch = scan.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         scan.userEmail?.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesRisk && matchesSearch;
  });

  const getRiskBadge = (riskLevel: string) => {
    const badges = {
      safe: 'bg-cyber-primary/20 text-cyber-primary border-cyber-primary/30',
      suspicious: 'bg-cyber-warning/20 text-cyber-warning border-cyber-warning/30',
      dangerous: 'bg-cyber-danger/20 text-cyber-danger border-cyber-danger/30'
    };
    return badges[riskLevel as keyof typeof badges] || badges.safe;
  };

  const getStatusBadge = (status: string) => {
    const badges = {
      pending: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      resolved: 'bg-cyber-primary/20 text-cyber-primary border-cyber-primary/30',
      open: 'bg-cyber-danger/20 text-cyber-danger border-cyber-danger/30',
      assigned: 'bg-cyber-accent/20 text-cyber-accent border-cyber-accent/30'
    };
    return badges[status as keyof typeof badges] || badges.pending;
  };

  const stats = [
    { label: 'Total Scans', value: scanLogs.length, icon: Shield, color: 'blue' },
    { label: 'High Risk', value: scanLogs.filter(s => s.riskLevel === 'dangerous').length, icon: AlertTriangle, color: 'red' },
    { label: 'Pending Review', value: scanLogs.filter(s => s.status === 'pending').length, icon: Clock, color: 'orange' },
    { label: 'Bug Reports', value: bugReports.length, icon: FileText, color: 'purple' }
  ];

  // User features that officers can access
  const userFeatures = [
    { id: 'url-scanner', label: 'URL Scanner', icon: Link, description: 'Monitor URL scanning activity' },
    { id: 'qr-scanner', label: 'QR Scanner', icon: QrCode, description: 'Review QR code analysis' },
    { id: 'file-upload', label: 'File Analysis', icon: Upload, description: 'Check file scanning results' },
    { id: 'threat-monitor', label: 'Threat Intelligence', icon: Activity, description: 'View threat monitoring data' },
    { id: 'incident-response', label: 'Incident Response', icon: AlertTriangle, description: 'Manage security incidents' },
    { id: 'vulnerability-management', label: 'Vulnerability Management', icon: Target, description: 'Review system vulnerabilities' },
    { id: 'data-loss-prevention', label: 'Data Loss Prevention', icon: Database, description: 'Monitor data transfers' },
    { id: 'forensics-audit', label: 'Digital Forensics', icon: Search, description: 'Access forensic evidence' },
    { id: 'ai-ml-integration', label: 'AI/ML Analytics', icon: Brain, description: 'View AI security insights' }
  ];

  return (
    <div className="min-h-screen bg-cyber-darker relative overflow-hidden">
      {/* Cyberpunk background effects */}
      <div className="absolute inset-0 cyber-grid opacity-20"></div>
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_80%,rgba(255,0,64,0.1),transparent)]"></div>
      <div className="hex-grid opacity-10"></div>
      
      {/* Floating icons */}
      {floatingIcons.map((item, index) => (
        <div 
          key={index}
          className="absolute text-cyber-danger/5 pointer-events-none"
          style={{
            left: `${item.x}%`,
            top: `${item.y}%`,
            width: `${item.size}px`,
            height: `${item.size}px`,
            transform: `rotate(${item.rotation}deg)`,
            animation: `cyber-float ${item.speed}s ease-in-out infinite alternate`
          }}
        >
          <item.icon size={item.size} />
        </div>
      ))}
      
      {/* Scan lines */}
      {scanLines.map((top, i) => (
        <div 
          key={i}
          className="absolute left-0 w-full h-px bg-cyber-danger/10"
          style={{ 
            top: `${top}%`,
            animation: `scan-line ${2 + Math.random() * 4}s linear infinite`,
            animationDelay: `${Math.random() * 2}s`
          }}
        ></div>
      ))}
      
      {/* Header */}
      <div className="bg-black/90 backdrop-blur-md border-b border-cyber-danger/20 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-3">
              <div className="relative">
                <Shield className="w-8 h-8 text-cyber-danger" />
                <div className="absolute inset-0 animate-cyber-pulse">
                  <Shield className="w-8 h-8 text-cyber-danger/50" />
                </div>
              </div>
              <div>
                <span className="text-xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyber-danger to-cyber-warning font-cyber">
                  THREATOPS COMMAND CENTER
                </span>
                <div className="text-xs text-gray-400 font-cyber-alt">OFFICER PANEL • CLASSIFIED</div>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <div className="text-sm font-medium text-white font-cyber">{officer?.fullName}</div>
                <div className="text-xs text-gray-400 font-cyber-alt">{officer?.department}</div>
              </div>
              <button
                onClick={handleLogout}
                className="cyber-button px-4 py-2 rounded-lg text-sm border-cyber-danger text-cyber-danger"
              >
                <LogOut className="w-4 h-4 mr-2" />
                <span className="font-cyber">LOGOUT</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Terminal Window */}
        <div className={`cyber-card p-4 mb-8 border-cyber-danger/30 transition-all duration-300 ${maximized ? 'fixed inset-4 z-50' : ''}`}>
          <div className="flex items-center justify-between mb-2 border-b border-cyber-danger/20 pb-2">
            <div className="flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-cyber-danger" />
              <span className="text-cyber-danger font-cyber text-sm">SYSTEM TERMINAL</span>
            </div>
            <div className="flex items-center space-x-2">
              <button 
                onClick={() => setMaximized(!maximized)}
                className="text-gray-400 hover:text-cyber-danger transition-colors"
              >
                {maximized ? <Minimize className="w-4 h-4" /> : <Maximize className="w-4 h-4" />}
              </button>
            </div>
          </div>
          <div className={`font-mono text-xs text-cyber-danger overflow-auto ${maximized ? 'h-[calc(100vh-8rem)]' : 'h-32'}`}>
            {terminalLines.map((line, index) => (
              <div key={index} className="mb-1">
                <span className="text-gray-500">[{new Date().toLocaleTimeString()}]</span> {line}
              </div>
            ))}
            <div className="flex items-center">
              <span className="text-gray-500">[{new Date().toLocaleTimeString()}]</span> 
              <span className="text-cyber-danger ml-1">root@threatops:~# </span>
              <span className={`inline-block w-2 h-4 bg-cyber-danger ml-1 ${terminalCursor ? 'opacity-100' : 'opacity-0'}`}></span>
            </div>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {stats.map((stat, index) => {
            const Icon = stat.icon;
            const colorClasses = {
              blue: 'from-cyber-accent/20 to-cyber-accent/10 border-cyber-accent/30 text-cyber-accent',
              red: 'from-cyber-danger/20 to-cyber-danger/10 border-cyber-danger/30 text-cyber-danger',
              orange: 'from-cyber-warning/20 to-cyber-warning/10 border-cyber-warning/30 text-cyber-warning',
              purple: 'from-purple-500/20 to-purple-600/20 border-purple-500/30 text-purple-400'
            };
            
            return (
              <div
                key={index}
                className={`cyber-card bg-gradient-to-br ${colorClasses[stat.color as keyof typeof colorClasses]} p-6 relative overflow-hidden`}
              >
                {/* Animated circuit pattern */}
                <div className="absolute inset-0 pointer-events-none opacity-10">
                  <svg width="100%" height="100%" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                    <path d="M10,10 L90,10 L90,90 L10,90 Z" fill="none" stroke="currentColor" strokeWidth="0.5" />
                    <path d="M20,20 L80,20 L80,80 L20,80 Z" fill="none" stroke="currentColor" strokeWidth="0.5" />
                    <circle cx="10" cy="10" r="2" fill="currentColor" />
                    <circle cx="90" cy="10" r="2" fill="currentColor" />
                    <circle cx="10" cy="90" r="2" fill="currentColor" />
                    <circle cx="90" cy="90" r="2" fill="currentColor" />
                  </svg>
                </div>
                
                <div className="flex items-center justify-between mb-4 relative">
                  <Icon className="w-8 h-8" />
                  <div className="text-2xl font-bold text-white font-cyber">{stat.value}</div>
                </div>
                <div className="text-sm opacity-80 font-cyber-alt relative">{stat.label}</div>
              </div>
            );
          })}
        </div>

        {/* Tab Navigation */}
        <div className="cyber-card p-2 mb-8 border-gray-700/50">
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`px-4 py-3 rounded-xl font-medium transition-all duration-200 font-cyber ${
                activeTab === 'dashboard'
                  ? 'bg-cyber-accent/20 text-cyber-accent border border-cyber-accent/30'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700/30'
              }`}
            >
              📊 DASHBOARD
            </button>
            <button
              onClick={() => setActiveTab('scans')}
              className={`px-4 py-3 rounded-xl font-medium transition-all duration-200 font-cyber ${
                activeTab === 'scans'
                  ? 'bg-cyber-danger/20 text-cyber-danger border border-cyber-danger/30'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700/30'
              }`}
            >
              🔍 SCAN LOGS
            </button>
            <button
              onClick={() => setActiveTab('bugs')}
              className={`px-4 py-3 rounded-xl font-medium transition-all duration-200 font-cyber ${
                activeTab === 'bugs'
                  ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700/30'
              }`}
            >
              🐛 BUG REPORTS
            </button>
            <button
              onClick={() => setActiveTab('user-features')}
              className={`px-4 py-3 rounded-xl font-medium transition-all duration-200 font-cyber ${
                activeTab === 'user-features'
                  ? 'bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/30'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700/30'
              }`}
            >
              👁️ USER FEATURES
            </button>
          </div>
        </div>

        {/* Dashboard Tab */}
        {activeTab === 'dashboard' && (
          <div className="space-y-8">
            {/* Security Overview */}
            <div className="cyber-card p-6 border-cyber-accent/30 bg-gradient-to-r from-cyber-accent/5 to-transparent">
              <h2 className="text-2xl font-bold text-white mb-6 font-cyber flex items-center">
                <Shield className="w-6 h-6 mr-3 text-cyber-accent" />
                SECURITY OVERVIEW
              </h2>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Threat Stats */}
                <div className="cyber-card p-4 border-gray-700/50 bg-black/30">
                  <h3 className="text-lg font-bold text-white mb-4 font-cyber flex items-center">
                    <AlertTriangle className="w-5 h-5 mr-2 text-cyber-danger" />
                    THREAT STATISTICS
                  </h3>
                  
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300 font-cyber-alt">Active Threats</span>
                      <span className="text-cyber-danger font-bold font-cyber">23</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300 font-cyber-alt">Blocked Attacks</span>
                      <span className="text-cyber-primary font-bold font-cyber">142</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300 font-cyber-alt">Suspicious Activities</span>
                      <span className="text-cyber-warning font-bold font-cyber">56</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300 font-cyber-alt">Data Breaches</span>
                      <span className="text-cyber-danger font-bold font-cyber">2</span>
                    </div>
                  </div>
                </div>
                
                {/* System Status */}
                <div className="cyber-card p-4 border-gray-700/50 bg-black/30">
                  <h3 className="text-lg font-bold text-white mb-4 font-cyber flex items-center">
                    <Activity className="w-5 h-5 mr-2 text-cyber-primary" />
                    SYSTEM STATUS
                  </h3>
                  
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300 font-cyber-alt">Firewall Status</span>
                      <span className="text-cyber-primary font-bold font-cyber">ACTIVE</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300 font-cyber-alt">IDS/IPS</span>
                      <span className="text-cyber-primary font-bold font-cyber">MONITORING</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300 font-cyber-alt">Endpoint Protection</span>
                      <span className="text-cyber-primary font-bold font-cyber">98% COVERAGE</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300 font-cyber-alt">Patch Status</span>
                      <span className="text-cyber-warning font-bold font-cyber">3 PENDING</span>
                    </div>
                  </div>
                </div>
                
                {/* Officer Activity */}
                <div className="cyber-card p-4 border-gray-700/50 bg-black/30">
                  <h3 className="text-lg font-bold text-white mb-4 font-cyber flex items-center">
                    <Users className="w-5 h-5 mr-2 text-cyber-accent" />
                    OFFICER ACTIVITY
                  </h3>
                  
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300 font-cyber-alt">Active Officers</span>
                      <span className="text-cyber-accent font-bold font-cyber">4</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300 font-cyber-alt">Incidents Handled</span>
                      <span className="text-cyber-accent font-bold font-cyber">17</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300 font-cyber-alt">Response Time</span>
                      <span className="text-cyber-accent font-bold font-cyber">4.2 MIN</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300 font-cyber-alt">Shift Status</span>
                      <span className="text-cyber-primary font-bold font-cyber">ACTIVE</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            
            {/* Threat Map */}
            <div className="cyber-card p-6 border-cyber-danger/30">
              <h2 className="text-2xl font-bold text-white mb-6 font-cyber flex items-center">
                <Globe className="w-6 h-6 mr-3 text-cyber-danger" />
                GLOBAL THREAT MAP
              </h2>
              
              <div className="relative h-64 bg-black/50 rounded-xl border border-gray-700/50 overflow-hidden">
                {/* World map background */}
                <div className="absolute inset-0 opacity-20">
                  <svg viewBox="0 0 1000 500" xmlns="http://www.w3.org/2000/svg">
                    <path d="M473,208L522,208L544,222L551,245L527,259L504,259L473,245Z" fill="none" stroke="#ff0040" strokeWidth="1"/>
                    <path d="M322,116L350,116L371,130L371,151L350,165L322,165L301,151L301,130Z" fill="none" stroke="#ff0040" strokeWidth="1"/>
                    <path d="M151,190L179,190L200,204L200,225L179,239L151,239L130,225L130,204Z" fill="none" stroke="#ff0040" strokeWidth="1"/>
                    <path d="M671,190L699,190L720,204L720,225L699,239L671,239L650,225L650,204Z" fill="none" stroke="#ff0040" strokeWidth="1"/>
                    <path d="M822,116L850,116L871,130L871,151L850,165L822,165L801,151L801,130Z" fill="none" stroke="#ff0040" strokeWidth="1"/>
                    <path d="M473,308L522,308L544,322L551,345L527,359L504,359L473,345Z" fill="none" stroke="#ff0040" strokeWidth="1"/>
                    <path d="M100,100L900,100L900,400L100,400Z" fill="none" stroke="#ff0040" strokeWidth="1"/>
                  </svg>
                </div>
                
                {/* Threat indicators */}
                <div className="absolute h-3 w-3 rounded-full bg-cyber-danger animate-pulse" style={{ top: '30%', left: '20%' }}></div>
                <div className="absolute h-4 w-4 rounded-full bg-cyber-danger animate-pulse" style={{ top: '40%', left: '70%' }}></div>
                <div className="absolute h-2 w-2 rounded-full bg-cyber-danger animate-pulse" style={{ top: '60%', left: '50%' }}></div>
                <div className="absolute h-3 w-3 rounded-full bg-cyber-warning animate-pulse" style={{ top: '25%', left: '80%' }}></div>
                <div className="absolute h-3 w-3 rounded-full bg-cyber-warning animate-pulse" style={{ top: '50%', left: '30%' }}></div>
                
                {/* Connection lines */}
                <svg className="absolute inset-0 w-full h-full" xmlns="http://www.w3.org/2000/svg">
                  <line x1="20%" y1="30%" x2="70%" y2="40%" stroke="#ff0040" strokeWidth="1" strokeDasharray="5,5">
                    <animate attributeName="stroke-dashoffset" from="0" to="10" dur="1s" repeatCount="indefinite" />
                  </line>
                  <line x1="80%" y1="25%" x2="50%" y2="60%" stroke="#ffaa00" strokeWidth="1" strokeDasharray="5,5">
                    <animate attributeName="stroke-dashoffset" from="0" to="10" dur="1.5s" repeatCount="indefinite" />
                  </line>
                  <line x1="30%" y1="50%" x2="50%" y2="60%" stroke="#ffaa00" strokeWidth="1" strokeDasharray="5,5">
                    <animate attributeName="stroke-dashoffset" from="0" to="10" dur="2s" repeatCount="indefinite" />
                  </line>
                </svg>
                
                {/* Overlay text */}
                <div className="absolute bottom-4 left-4 text-xs text-cyber-danger font-mono">
                  ACTIVE THREATS: 23 | CRITICAL: 5 | HIGH: 12 | MEDIUM: 6
                </div>
                
                {/* Scan line effect */}
                <div className="absolute inset-0 overflow-hidden">
                  <div className="absolute top-0 left-0 w-full h-px bg-cyber-danger/30 animate-cyber-scan"></div>
                </div>
              </div>
            </div>
            
            {/* Charts and Analytics */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Threat Distribution */}
              <div className="cyber-card p-6 border-gray-700/50">
                <h3 className="text-lg font-bold text-white mb-4 font-cyber flex items-center">
                  <PieChart className="w-5 h-5 mr-2 text-cyber-warning" />
                  THREAT DISTRIBUTION
                </h3>
                
                <div className="relative h-48 flex items-center justify-center">
                  {/* Mock pie chart */}
                  <div className="relative w-32 h-32">
                    <svg viewBox="0 0 100 100" className="w-full h-full">
                      <circle cx="50" cy="50" r="45" fill="transparent" stroke="#ff0040" strokeWidth="10" strokeDasharray="70.7 282.8" />
                      <circle cx="50" cy="50" r="45" fill="transparent" stroke="#ffaa00" strokeWidth="10" strokeDasharray="113.1 282.8" strokeDashoffset="-70.7" />
                      <circle cx="50" cy="50" r="45" fill="transparent" stroke="#00ff41" strokeWidth="10" strokeDasharray="99 282.8" strokeDashoffset="-183.8" />
                    </svg>
                    <div className="absolute inset-0 flex items-center justify-center">
                      <div className="text-xs text-white font-cyber">THREATS</div>
                    </div>
                  </div>
                  
                  {/* Legend */}
                  <div className="absolute right-0 top-0 bottom-0 flex flex-col justify-center space-y-3">
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-cyber-danger"></div>
                      <span className="text-xs text-gray-300">Malware (25%)</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-cyber-warning"></div>
                      <span className="text-xs text-gray-300">Phishing (40%)</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-cyber-primary"></div>
                      <span className="text-xs text-gray-300">Other (35%)</span>
                    </div>
                  </div>
                </div>
              </div>
              
              {/* Activity Timeline */}
              <div className="cyber-card p-6 border-gray-700/50">
                <h3 className="text-lg font-bold text-white mb-4 font-cyber flex items-center">
                  <BarChart className="w-5 h-5 mr-2 text-cyber-accent" />
                  ACTIVITY TIMELINE
                </h3>
                
                <div className="relative h-48">
                  {/* Mock bar chart */}
                  <div className="absolute inset-0 flex items-end justify-between px-2">
                    {[35, 65, 40, 80, 55, 70, 90].map((height, index) => (
                      <div key={index} className="w-8 bg-gradient-to-t from-cyber-accent to-cyber-accent/30 rounded-t" style={{ height: `${height}%` }}>
                        <div className="absolute bottom-full w-full text-center text-xs text-cyber-accent mb-1">{height}</div>
                      </div>
                    ))}
                  </div>
                  
                  {/* X-axis labels */}
                  <div className="absolute bottom-0 left-0 right-0 flex justify-between px-2 pt-2 border-t border-gray-700/50">
                    {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map((day, index) => (
                      <div key={index} className="w-8 text-center text-xs text-gray-400">{day}</div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
            
            {/* Recent Alerts */}
            <div className="cyber-card p-6 border-cyber-danger/30">
              <h2 className="text-2xl font-bold text-white mb-6 font-cyber flex items-center">
                <AlertTriangle className="w-6 h-6 mr-3 text-cyber-danger" />
                RECENT ALERTS
              </h2>
              
              <div className="space-y-4">
                {scanLogs.filter(scan => scan.riskLevel === 'dangerous').slice(0, 3).map((scan) => (
                  <div
                    key={scan.id}
                    className="flex items-center justify-between p-4 bg-black/30 rounded-xl border border-cyber-danger/30 hover:border-cyber-danger/50 transition-colors"
                  >
                    <div className="flex items-center space-x-4">
                      <div className="w-10 h-10 bg-cyber-danger/20 rounded-lg flex items-center justify-center">
                        {scan.type === 'url' ? (
                          <Link className="w-5 h-5 text-cyber-danger" />
                        ) : (
                          <Upload className="w-5 h-5 text-cyber-danger" />
                        )}
                      </div>
                      <div>
                        <div className="text-white font-medium font-cyber-alt">{scan.target}</div>
                        <div className="text-gray-400 text-sm">
                          {scan.type.toUpperCase()} • {scan.timestamp.toLocaleTimeString()}
                        </div>
                      </div>
                    </div>
                    <div className="flex space-x-2">
                      <span className="px-3 py-1 rounded border text-xs font-medium font-cyber bg-cyber-danger/20 text-cyber-danger border-cyber-danger/30">
                        CRITICAL
                      </span>
                      <button
                        onClick={() => handleViewScan(scan)}
                        className="p-2 bg-gray-800/50 hover:bg-gray-700/50 rounded-lg transition-colors"
                      >
                        <Eye className="w-4 h-4 text-gray-400" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
              
              <div className="mt-4 text-center">
                <button
                  onClick={() => setActiveTab('scans')}
                  className="text-cyber-danger hover:text-cyber-danger/80 font-medium transition-colors font-cyber"
                >
                  VIEW ALL ALERTS →
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Scan Logs Tab */}
        {activeTab === 'scans' && (
          <div className="cyber-card p-8 border-gray-700/50">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-white font-cyber">LIVE SCAN ACTIVITY</h2>
              
              {/* Filters */}
              <div className="flex space-x-4">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search scans..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10 pr-4 py-2 bg-black/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-danger/50"
                  />
                </div>
                
                <select
                  value={filterRisk}
                  onChange={(e) => setFilterRisk(e.target.value)}
                  className="px-4 py-2 bg-black/50 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyber-danger/50"
                >
                  <option value="all">All Risk Levels</option>
                  <option value="dangerous">High Risk</option>
                  <option value="suspicious">Medium Risk</option>
                  <option value="safe">Low Risk</option>
                </select>
              </div>
            </div>

            {/* Scan Table */}
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-4 text-gray-300 font-medium font-cyber">User</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-medium font-cyber">Type</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-medium font-cyber">Target</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-medium font-cyber">Risk</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-medium font-cyber">Status</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-medium font-cyber">Time</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-medium font-cyber">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredScans.map((scan) => (
                    <tr key={scan.id} className="border-b border-gray-800 hover:bg-gray-800/30">
                      <td className="py-4 px-4">
                        <div className="text-white font-medium font-cyber-alt">{scan.userEmail}</div>
                      </td>
                      <td className="py-4 px-4">
                        <span className={`px-2 py-1 rounded text-xs font-medium font-cyber ${
                          scan.type === 'url' ? 'bg-cyber-accent/20 text-cyber-accent' : 'bg-cyber-primary/20 text-cyber-primary'
                        }`}>
                          {scan.type.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-4 px-4">
                        <div className="text-gray-300 max-w-xs truncate font-mono text-sm">{scan.target}</div>
                      </td>
                      <td className="py-4 px-4">
                        <span className={`px-2 py-1 rounded border text-xs font-medium font-cyber ${getRiskBadge(scan.riskLevel)}`}>
                          {scan.riskLevel.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-4 px-4">
                        <span className={`px-2 py-1 rounded border text-xs font-medium font-cyber ${getStatusBadge(scan.status)}`}>
                          {scan.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-4 px-4 text-gray-400 text-sm font-mono">
                        {scan.timestamp.toLocaleString()}
                      </td>
                      <td className="py-4 px-4">
                        <div className="flex space-x-2">
                          {scan.status === 'pending' && (
                            <button
                              onClick={() => handleMarkResolved(scan.id)}
                              className="px-3 py-1 bg-cyber-primary/20 hover:bg-cyber-primary/30 text-cyber-primary rounded text-xs transition-colors font-cyber"
                            >
                              RESOLVE
                            </button>
                          )}
                          <button
                            onClick={() => handleViewScan(scan)}
                            className="px-3 py-1 bg-cyber-accent/20 hover:bg-cyber-accent/30 text-cyber-accent rounded text-xs transition-colors flex items-center space-x-1 font-cyber"
                          >
                            <Eye className="w-3 h-3" />
                            <span>VIEW</span>
                          </button>
                          <button
                            onClick={() => handleAddNotes(scan)}
                            className="px-3 py-1 bg-gray-600/20 hover:bg-gray-600/30 text-gray-400 rounded text-xs transition-colors font-cyber"
                          >
                            NOTES
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Bug Reports Tab */}
        {activeTab === 'bugs' && (
          <div className="cyber-card p-8 border-gray-700/50">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-white font-cyber">USER BUG REPORTS</h2>
            </div>

            <div className="space-y-6">
              {bugReports.map((bug) => (
                <div key={bug.id} className="cyber-card p-6 border-gray-700/50 relative overflow-hidden">
                  {/* Circuit pattern overlay */}
                  <div className="absolute inset-0 pointer-events-none opacity-5">
                    <svg width="100%" height="100%" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                      <path d="M10,10 L90,10 L90,90 L10,90 Z" fill="none" stroke="#ff0040" strokeWidth="0.5" />
                      <path d="M20,20 L80,20 L80,80 L20,80 Z" fill="none" stroke="#ff0040" strokeWidth="0.5" />
                      <path d="M10,10 L30,30" fill="none" stroke="#ff0040" strokeWidth="0.5" />
                      <path d="M90,10 L70,30" fill="none" stroke="#ff0040" strokeWidth="0.5" />
                      <path d="M10,90 L30,70" fill="none" stroke="#ff0040" strokeWidth="0.5" />
                      <path d="M90,90 L70,70" fill="none" stroke="#ff0040" strokeWidth="0.5" />
                      <circle cx="10" cy="10" r="2" fill="#ff0040" />
                      <circle cx="90" cy="10" r="2" fill="#ff0040" />
                      <circle cx="10" cy="90" r="2" fill="#ff0040" />
                      <circle cx="90" cy="90" r="2" fill="#ff0040" />
                    </svg>
                  </div>
                  
                  <div className="flex items-start justify-between mb-4 relative">
                    <div>
                      <h3 className="text-lg font-bold text-white mb-2 font-cyber">{bug.title}</h3>
                      <div className="flex items-center space-x-4 text-sm text-gray-400 font-cyber-alt">
                        <span>Bug #{bug.id}</span>
                        <span>From: {bug.userEmail}</span>
                        <span>{bug.timestamp.toLocaleString()}</span>
                      </div>
                    </div>
                    <span className={`px-3 py-1 rounded border text-xs font-medium font-cyber ${getStatusBadge(bug.status)}`}>
                      {bug.status.toUpperCase()}
                    </span>
                  </div>

                  <p className="text-gray-300 mb-4 font-cyber-alt relative">{bug.description}</p>

                  {bug.url && (
                    <div className="mb-4 relative">
                      <span className="text-sm text-gray-400 font-cyber">Related URL: </span>
                      <span className="text-cyber-accent font-mono">{bug.url}</span>
                    </div>
                  )}

                  {bug.aiSuggestion && (
                    <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-4 mb-4 relative">
                      <h4 className="text-purple-400 font-medium mb-2 font-cyber flex items-center">
                        <Brain className="w-4 h-4 mr-2" />
                        AI SUGGESTION:
                      </h4>
                      <p className="text-gray-300 text-sm font-cyber-alt">{bug.aiSuggestion}</p>
                    </div>
                  )}

                  <div className="flex space-x-3 relative">
                    {bug.status === 'open' && (
                      <button
                        onClick={() => handleAssignBug(bug.id)}
                        className="cyber-button px-4 py-2 rounded-lg text-sm border-cyber-accent text-cyber-accent font-cyber"
                      >
                        ASSIGN TO ME
                      </button>
                    )}
                    {bug.status === 'assigned' && (
                      <button
                        onClick={() => handleResolveBug(bug.id, 'Issue resolved by officer')}
                        className="cyber-button px-4 py-2 rounded-lg text-sm border-cyber-primary text-cyber-primary font-cyber"
                      >
                        MARK RESOLVED
                      </button>
                    )}
                    <button
                      onClick={() => handleViewBug(bug)}
                      className="cyber-button px-4 py-2 rounded-lg text-sm flex items-center space-x-2 border-cyber-accent text-cyber-accent font-cyber"
                    >
                      <Eye className="w-4 h-4" />
                      <span>VIEW DETAILS</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* User Features Tab */}
        {activeTab === 'user-features' && (
          <div className="cyber-card p-8 border-gray-700/50">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-white font-cyber">USER FEATURES MONITORING</h2>
              <div className="px-3 py-1 bg-cyber-primary/20 text-cyber-primary rounded-lg text-sm font-cyber">
                OFFICER ACCESS ENABLED
              </div>
            </div>

            <p className="text-gray-300 mb-6 font-cyber-alt">
              As an officer, you have access to all user features for monitoring purposes. Select any feature below to access the same tools that users can access, allowing you to monitor activity and investigate security issues.
            </p>

            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
              {userFeatures.map((feature) => {
                const Icon = feature.icon;
                return (
                  <div
                    key={feature.id}
                    onClick={() => onNavigate(feature.id)}
                    className="cyber-card p-6 cursor-pointer transition-all duration-300 hover:scale-105 border-gray-700/50 hover:border-cyber-primary/30 relative overflow-hidden group"
                  >
                    {/* Animated circuit pattern */}
                    <div className="absolute inset-0 pointer-events-none opacity-5 group-hover:opacity-10 transition-opacity">
                      <svg width="100%" height="100%" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                        <path d="M10,10 L90,10 L90,90 L10,90 Z" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                        <path d="M20,20 L80,20 L80,80 L20,80 Z" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                        <path d="M10,10 L30,30" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                        <path d="M90,10 L70,30" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                        <path d="M10,90 L30,70" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                        <path d="M90,90 L70,70" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                        <circle cx="10" cy="10" r="2" fill="#00ff41" />
                        <circle cx="90" cy="10" r="2" fill="#00ff41" />
                        <circle cx="10" cy="90" r="2" fill="#00ff41" />
                        <circle cx="90" cy="90" r="2" fill="#00ff41" />
                      </svg>
                    </div>
                    
                    {/* Scan line effect on hover */}
                    <div className="absolute inset-0 overflow-hidden opacity-0 group-hover:opacity-100 transition-opacity">
                      <div className="absolute top-0 left-0 w-full h-px bg-cyber-primary/30 transform -translate-x-full group-hover:translate-x-full transition-transform duration-1000"></div>
                    </div>
                    
                    <div className="flex items-center space-x-4 mb-3 relative">
                      <div className="p-3 bg-black/50 rounded-xl">
                        <Icon className="w-6 h-6 text-cyber-primary" />
                      </div>
                      <div>
                        <h3 className="text-lg font-bold text-white font-cyber">{feature.label}</h3>
                      </div>
                    </div>
                    <p className="text-gray-400 text-sm mb-4 font-cyber-alt relative">{feature.description}</p>
                    <div className="flex items-center text-cyber-primary text-sm relative">
                      <span className="font-cyber">ACCESS FEATURE</span>
                      <ArrowRight className="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform" />
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="mt-8 p-4 bg-cyber-danger/10 border border-cyber-danger/30 rounded-lg">
              <div className="flex items-start space-x-3">
                <AlertTriangle className="w-5 h-5 text-cyber-danger flex-shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-cyber-danger font-medium mb-1 font-cyber">OFFICER MONITORING MODE</h4>
                  <p className="text-gray-300 text-sm font-cyber-alt">
                    When accessing user features, you will be in monitoring mode. Any actions you take will be logged with your officer credentials. This ensures proper audit trails for all security operations.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* View Modal */}
        {viewModalOpen && (selectedScan || selectedBug) && (
          <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="cyber-card p-8 max-w-4xl w-full max-h-[90vh] overflow-y-auto border-cyber-primary/30 relative">
              {/* Circuit pattern overlay */}
              <div className="absolute inset-0 pointer-events-none opacity-5">
                <svg width="100%" height="100%" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                  <path d="M10,10 L90,10 L90,90 L10,90 Z" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                  <path d="M20,20 L80,20 L80,80 L20,80 Z" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                  <path d="M30,30 L70,30 L70,70 L30,70 Z" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                  <path d="M10,10 L30,30" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                  <path d="M90,10 L70,30" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                  <path d="M10,90 L30,70" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                  <path d="M90,90 L70,70" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                  <circle cx="10" cy="10" r="2" fill="#00ff41" />
                  <circle cx="90" cy="10" r="2" fill="#00ff41" />
                  <circle cx="10" cy="90" r="2" fill="#00ff41" />
                  <circle cx="90" cy="90" r="2" fill="#00ff41" />
                </svg>
              </div>
              
              <div className="flex items-center justify-between mb-6 relative">
                <h3 className="text-2xl font-bold text-white font-cyber">
                  {selectedScan ? 'SCAN DETAILS' : 'BUG REPORT DETAILS'}
                </h3>
                <button
                  onClick={() => {
                    setViewModalOpen(false);
                    setSelectedScan(null);
                    setBugReport(null);
                  }}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <X className="w-6 h-6" />
                </button>
              </div>

              {selectedScan && (
                <div className="space-y-6 relative">
                  <div className="grid grid-cols-2 gap-6">
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">USER EMAIL</h4>
                      <p className="text-white font-cyber-alt">{selectedScan.userEmail}</p>
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">SCAN TYPE</h4>
                      <p className="text-white font-cyber-alt">{selectedScan.type.toUpperCase()}</p>
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">TARGET</h4>
                      <p className="text-white break-all font-mono text-sm">{selectedScan.target}</p>
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">RISK LEVEL</h4>
                      <span className={`px-3 py-1 rounded border text-sm font-medium font-cyber ${getRiskBadge(selectedScan.riskLevel)}`}>
                        {selectedScan.riskLevel.toUpperCase()}
                      </span>
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">STATUS</h4>
                      <span className={`px-3 py-1 rounded border text-sm font-medium font-cyber ${getStatusBadge(selectedScan.status)}`}>
                        {selectedScan.status.toUpperCase()}
                      </span>
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">TIMESTAMP</h4>
                      <p className="text-white font-mono text-sm">{selectedScan.timestamp.toLocaleString()}</p>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">AI ANALYSIS REPORT</h4>
                    <div className="bg-black/50 border border-gray-700 rounded-lg p-4">
                      <pre className="text-gray-300 whitespace-pre-wrap text-sm leading-relaxed font-cyber-alt">
                        {selectedScan.report}
                      </pre>
                    </div>
                  </div>

                  {selectedScan.officerNotes && (
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">OFFICER NOTES</h4>
                      <div className="bg-cyber-accent/10 border border-cyber-accent/20 rounded-lg p-4">
                        <p className="text-cyber-accent font-cyber-alt">{selectedScan.officerNotes}</p>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {selectedBug && (
                <div className="space-y-6 relative">
                  <div className="grid grid-cols-2 gap-6">
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">BUG ID</h4>
                      <p className="text-white font-cyber-alt">#{selectedBug.id}</p>
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">USER EMAIL</h4>
                      <p className="text-white font-cyber-alt">{selectedBug.userEmail}</p>
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">STATUS</h4>
                      <span className={`px-3 py-1 rounded border text-sm font-medium font-cyber ${getStatusBadge(selectedBug.status)}`}>
                        {selectedBug.status.toUpperCase()}
                      </span>
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">SUBMITTED</h4>
                      <p className="text-white font-mono text-sm">{selectedBug.timestamp.toLocaleString()}</p>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">TITLE</h4>
                    <p className="text-white text-lg font-medium font-cyber">{selectedBug.title}</p>
                  </div>

                  <div>
                    <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">DESCRIPTION</h4>
                    <div className="bg-black/50 border border-gray-700 rounded-lg p-4">
                      <p className="text-gray-300 leading-relaxed font-cyber-alt">{selectedBug.description}</p>
                    </div>
                  </div>

                  {selectedBug.url && (
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">RELATED URL</h4>
                      <p className="text-cyber-accent break-all font-mono text-sm">{selectedBug.url}</p>
                    </div>
                  )}

                  {selectedBug.aiSuggestion && (
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">AI SUGGESTION</h4>
                      <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-4">
                        <p className="text-purple-300 font-cyber-alt">{selectedBug.aiSuggestion}</p>
                      </div>
                    </div>
                  )}

                  {selectedBug.assignedOfficer && (
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">ASSIGNED OFFICER</h4>
                      <p className="text-white font-cyber-alt">{selectedBug.assignedOfficer}</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Notes Modal */}
        {notesModalOpen && selectedScan && (
          <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="cyber-card p-8 max-w-2xl w-full border-cyber-primary/30 relative">
              {/* Circuit pattern overlay */}
              <div className="absolute inset-0 pointer-events-none opacity-5">
                <svg width="100%" height="100%" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                  <path d="M10,10 L90,10 L90,90 L10,90 Z" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                  <path d="M20,20 L80,20 L80,80 L20,80 Z" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                  <path d="M10,10 L30,30" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                  <path d="M90,10 L70,30" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                  <path d="M10,90 L30,70" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                  <path d="M90,90 L70,70" fill="none" stroke="#00ff41" strokeWidth="0.5" />
                  <circle cx="10" cy="10" r="2" fill="#00ff41" />
                  <circle cx="90" cy="10" r="2" fill="#00ff41" />
                  <circle cx="10" cy="90" r="2" fill="#00ff41" />
                  <circle cx="90" cy="90" r="2" fill="#00ff41" />
                </svg>
              </div>
              
              <div className="flex items-center justify-between mb-6 relative">
                <h3 className="text-2xl font-bold text-white font-cyber">ADD OFFICER NOTES</h3>
                <button
                  onClick={() => {
                    setNotesModalOpen(false);
                    setSelectedScan(null);
                    setOfficerNotes('');
                  }}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <X className="w-6 h-6" />
                </button>
              </div>

              <div className="space-y-4 relative">
                <div>
                  <h4 className="text-sm font-medium text-gray-400 mb-2 font-cyber">SCAN TARGET</h4>
                  <p className="text-white break-all font-mono text-sm">{selectedScan.target}</p>
                </div>

                <div>
                  <label htmlFor="notes" className="block text-sm font-medium text-gray-400 mb-2 font-cyber">
                    OFFICER NOTES
                  </label>
                  <div className="relative">
                    <textarea
                      id="notes"
                      value={officerNotes}
                      onChange={(e) => setOfficerNotes(e.target.value)}
                      rows={6}
                      className="w-full px-4 py-3 bg-black/50 border border-cyber-primary/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-primary/50 focus:border-cyber-primary transition-all duration-200 resize-none"
                      placeholder="Add your analysis, findings, or resolution notes..."
                    />
                    
                    {/* Animated border effect */}
                    <div className="absolute inset-0 pointer-events-none">
                      <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-cyber-primary to-transparent transform -translate-x-full animate-cyber-scan"></div>
                    </div>
                  </div>
                </div>

                <div className="flex space-x-4 justify-end">
                  <button
                    onClick={() => {
                      setNotesModalOpen(false);
                      setSelectedScan(null);
                      setOfficerNotes('');
                    }}
                    className="px-6 py-2 bg-gray-600/20 hover:bg-gray-600/30 text-gray-400 rounded-lg transition-colors font-cyber"
                  >
                    CANCEL
                  </button>
                  <button
                    onClick={handleSaveNotes}
                    className="cyber-button px-6 py-2 rounded-lg flex items-center space-x-2 font-cyber"
                  >
                    <Save className="w-4 h-4" />
                    <span>SAVE NOTES</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        
      </div>
    </div>
  );
};

export default OfficerPanel;