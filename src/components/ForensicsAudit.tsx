import React, { useState, useEffect } from 'react';
import { Shield, Search, FileText, Clock, Users, Database, Activity, AlertTriangle, Download, Eye, Lock, CheckCircle, XCircle, Filter, Calendar, BarChart3, TrendingUp, Zap, Settings, Play, Pause } from 'lucide-react';
import { useAlert } from '../contexts/AlertContext';
import { ForensicCase, AuditLog, ForensicEvidence, ForensicTimelineEntry, SystemActivity, ComplianceAudit, ForensicDashboard, ChainOfCustodyEntry } from '../types';
import { ForensicsEngine } from '../utils/forensicsEngine';

interface ForensicsAuditProps {
  onNavigate: (page: string) => void;
}

const ForensicsAudit: React.FC<ForensicsAuditProps> = ({ onNavigate }) => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [cases, setCases] = useState<ForensicCase[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [evidence, setEvidence] = useState<ForensicEvidence[]>([]);
  const [timeline, setTimeline] = useState<ForensicTimelineEntry[]>([]);
  const [systemActivity, setSystemActivity] = useState<SystemActivity[]>([]);
  const [dashboard, setDashboard] = useState<ForensicDashboard | null>(null);
  const [selectedCase, setSelectedCase] = useState<ForensicCase | null>(null);
  const [selectedEvidence, setSelectedEvidence] = useState<ForensicEvidence | null>(null);
  const [filter, setFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d' | '30d'>('24h');
  const [isMonitoring, setIsMonitoring] = useState(true);
  const { addAlert } = useAlert();

  const forensicsEngine = new ForensicsEngine();

  useEffect(() => {
    loadMockData();
    
    // Simulate real-time activity monitoring
    if (isMonitoring) {
      const interval = setInterval(() => {
        simulateRealTimeActivity();
      }, 5000); // Check every 5 seconds

      return () => clearInterval(interval);
    }
  }, [isMonitoring]);

  const loadMockData = () => {
    // Mock Forensic Cases
    const mockCases: ForensicCase[] = [
      {
        id: 'CASE-001',
        caseNumber: 'FR-2024-001',
        title: 'Data Breach Investigation - Customer Database',
        description: 'Investigation into unauthorized access to customer database containing PII',
        status: 'investigating',
        priority: 'critical',
        caseType: 'breach_analysis',
        investigator: 'Agent Sarah Connor',
        assignedTeam: ['Digital Forensics Team', 'Incident Response'],
        createdAt: new Date(Date.now() - 86400000 * 2),
        updatedAt: new Date(Date.now() - 3600000),
        dueDate: new Date(Date.now() + 86400000 * 5),
        relatedIncidents: ['INC-001', 'INC-003'],
        evidence: [],
        timeline: [],
        chainOfCustody: [],
        findings: [],
        legalHold: true,
        retentionPeriod: 2555, // 7 years
        tags: ['data-breach', 'pii', 'database'],
        metadata: {
          affectedRecords: 50000,
          estimatedCost: 250000,
          regulatoryNotification: true
        }
      },
      {
        id: 'CASE-002',
        caseNumber: 'FR-2024-002',
        title: 'Insider Threat Analysis - Intellectual Property',
        description: 'Investigation of potential intellectual property theft by departing employee',
        status: 'analysis',
        priority: 'high',
        caseType: 'internal_investigation',
        investigator: 'Lt. John Matrix',
        assignedTeam: ['HR Security', 'Legal'],
        createdAt: new Date(Date.now() - 86400000 * 5),
        updatedAt: new Date(Date.now() - 7200000),
        dueDate: new Date(Date.now() + 86400000 * 10),
        relatedIncidents: ['INC-005'],
        evidence: [],
        timeline: [],
        chainOfCustody: [],
        findings: [],
        legalHold: true,
        retentionPeriod: 1825, // 5 years
        tags: ['insider-threat', 'ip-theft', 'employee'],
        metadata: {
          employee: 'John Smith',
          department: 'R&D',
          lastWorkDay: new Date(Date.now() - 86400000 * 3)
        }
      }
    ];

    // Mock Audit Logs
    const mockAuditLogs: AuditLog[] = [
      {
        id: 'AUDIT-001',
        timestamp: new Date(Date.now() - 1800000),
        eventType: 'evidence_access',
        userId: 'user123',
        userEmail: 'sarah.connor@company.com',
        userName: 'Sarah Connor',
        userRole: 'Forensic Investigator',
        sourceIP: '192.168.1.100',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        sessionId: 'sess_abc123',
        action: 'download_evidence',
        resource: 'disk_image_001.dd',
        resourceType: 'forensic_evidence',
        resourceId: 'EVID-001',
        outcome: 'success',
        details: {
          evidenceType: 'disk_image',
          fileSize: '500GB',
          downloadDuration: '45 minutes'
        },
        riskScore: 25,
        geolocation: {
          country: 'United States',
          region: 'California',
          city: 'San Francisco',
          latitude: 37.7749,
          longitude: -122.4194
        },
        deviceInfo: {
          deviceType: 'desktop',
          operatingSystem: 'Windows 10',
          browser: 'Chrome 120',
          fingerprint: 'fp_xyz789'
        },
        tags: ['evidence-access', 'authorized'],
        retention: new Date(Date.now() + 86400000 * 2555),
        archived: false
      },
      {
        id: 'AUDIT-002',
        timestamp: new Date(Date.now() - 3600000),
        eventType: 'authentication',
        userId: 'user456',
        userEmail: 'unknown@external.com',
        userName: 'Unknown User',
        userRole: 'guest',
        sourceIP: '203.0.113.42',
        userAgent: 'curl/7.68.0',
        sessionId: 'sess_def456',
        action: 'failed_login',
        resource: 'forensics_portal',
        resourceType: 'application',
        outcome: 'failure',
        details: {
          reason: 'invalid_credentials',
          attempts: 5,
          lockout: true
        },
        riskScore: 85,
        geolocation: {
          country: 'Unknown',
          region: 'Unknown',
          city: 'Unknown',
          latitude: 0,
          longitude: 0
        },
        tags: ['failed-login', 'suspicious', 'external'],
        retention: new Date(Date.now() + 86400000 * 2555),
        archived: false
      }
    ];

    // Mock Evidence
    const mockEvidence: ForensicEvidence[] = [
      {
        id: 'EVID-001',
        caseId: 'CASE-001',
        evidenceNumber: 'E001-2024',
        type: 'disk_image',
        description: 'Full disk image of compromised database server',
        source: 'DB-SERVER-01',
        location: '/evidence/disk_images/db_server_01.dd',
        size: 536870912000, // 500GB
        hash: {
          md5: 'a1b2c3d4e5f6g7h8i9j0',
          sha1: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
          sha256: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6',
          verifiedAt: new Date(),
          verifiedBy: 'Sarah Connor'
        },
        collectedBy: 'Sarah Connor',
        collectedAt: new Date(Date.now() - 86400000),
        acquisitionMethod: 'Live imaging with write blocker',
        acquisitionTool: 'FTK Imager 4.7',
        verified: true,
        encrypted: true,
        compressionType: 'gzip',
        metadata: {
          originalPath: '/dev/sda1',
          fileSystem: 'ext4',
          operatingSystem: 'Ubuntu 20.04 LTS',
          hostname: 'db-server-01',
          username: 'dbadmin',
          timezone: 'UTC-8'
        },
        chainOfCustody: [],
        analysis: [],
        tags: ['database', 'server', 'breach'],
        legalHold: true,
        retentionDate: new Date(Date.now() + 86400000 * 2555),
        accessLog: []
      }
    ];

    // Mock Dashboard Data
    const mockDashboard: ForensicDashboard = {
      activeCases: 12,
      evidenceItems: 156,
      pendingAnalysis: 23,
      complianceScore: 94,
      recentActivity: mockAuditLogs,
      casesByStatus: {
        'open': 3,
        'investigating': 5,
        'analysis': 2,
        'reporting': 1,
        'closed': 1
      },
      evidenceByType: {
        'disk_image': 45,
        'memory_dump': 32,
        'network_capture': 28,
        'log_file': 51
      },
      topInvestigators: [
        { name: 'Sarah Connor', cases: 8 },
        { name: 'John Matrix', cases: 6 },
        { name: 'Lisa Chen', cases: 4 }
      ],
      auditTrends: [
        { date: new Date(Date.now() - 86400000 * 6), events: 1250 },
        { date: new Date(Date.now() - 86400000 * 5), events: 1180 },
        { date: new Date(Date.now() - 86400000 * 4), events: 1320 },
        { date: new Date(Date.now() - 86400000 * 3), events: 1450 },
        { date: new Date(Date.now() - 86400000 * 2), events: 1380 },
        { date: new Date(Date.now() - 86400000 * 1), events: 1520 },
        { date: new Date(), events: 1680 }
      ],
      riskMetrics: {
        highRiskEvents: 45,
        failedLogins: 123,
        privilegedAccess: 67,
        dataExfiltration: 12
      }
    };

    setCases(mockCases);
    setAuditLogs(mockAuditLogs);
    setEvidence(mockEvidence);
    setDashboard(mockDashboard);
  };

  const simulateRealTimeActivity = () => {
    if (Math.random() < 0.4) { // 40% chance of new activity
      const newActivity = forensicsEngine.generateMockAuditLog();
      setAuditLogs(prev => [newActivity, ...prev.slice(0, 99)]);

      // Auto-alert for high-risk events
      if (newActivity.riskScore >= 80) {
        addAlert({
          type: 'ForensicEvent',
          userEmail: newActivity.userEmail,
          message: `🔍 High-risk forensic event: ${newActivity.action} by ${newActivity.userName}`,
          status: 'unread',
          relatedId: newActivity.id,
          priority: 'high'
        });
      }

      // Update dashboard stats
      if (dashboard) {
        setDashboard(prev => prev ? {
          ...prev,
          recentActivity: [newActivity, ...prev.recentActivity.slice(0, 9)]
        } : null);
      }
    }
  };

  const handleCaseAction = (caseId: string, action: string) => {
    setCases(prev => prev.map(case_ => 
      case_.id === caseId 
        ? { ...case_, status: action as any, updatedAt: new Date() }
        : case_
    ));
  };

  const generateCaseReport = (case_: ForensicCase) => {
    const report = forensicsEngine.generateCaseReport(case_);
    
    // Create and download the report
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensic_report_${case_.caseNumber}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'text-blue-400 bg-blue-500/20 border-blue-500/30';
      case 'investigating': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
      case 'analysis': return 'text-purple-400 bg-purple-500/20 border-purple-500/30';
      case 'reporting': return 'text-orange-400 bg-orange-500/20 border-orange-500/30';
      case 'closed': return 'text-green-400 bg-green-500/20 border-green-500/30';
      default: return 'text-gray-400 bg-gray-500/20 border-gray-500/30';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'text-red-400 bg-red-500/20 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/20 border-orange-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
      case 'low': return 'text-blue-400 bg-blue-500/20 border-blue-500/30';
      default: return 'text-gray-400 bg-gray-500/20 border-gray-500/30';
    }
  };

  const getEvidenceTypeIcon = (type: string) => {
    switch (type) {
      case 'disk_image': return '💾';
      case 'memory_dump': return '🧠';
      case 'network_capture': return '🌐';
      case 'log_file': return '📄';
      case 'email': return '📧';
      case 'document': return '📋';
      case 'database_export': return '🗄️';
      case 'mobile_backup': return '📱';
      case 'cloud_data': return '☁️';
      default: return '📁';
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const filteredAuditLogs = auditLogs.filter(log => {
    const now = new Date();
    const timeRangeMs = {
      '1h': 3600000,
      '24h': 86400000,
      '7d': 604800000,
      '30d': 2592000000
    };
    
    const cutoff = new Date(now.getTime() - timeRangeMs[timeRange]);
    const timeMatch = log.timestamp >= cutoff;
    
    const riskMatch = filter === 'all' || 
      (filter === 'critical' && log.riskScore >= 90) ||
      (filter === 'high' && log.riskScore >= 70 && log.riskScore < 90) ||
      (filter === 'medium' && log.riskScore >= 40 && log.riskScore < 70) ||
      (filter === 'low' && log.riskScore < 40);
    
    return timeMatch && riskMatch;
  });

  return (
    <div className="min-h-screen bg-gradient-to-br from-black via-gray-900 to-black">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_80%,rgba(99,102,241,0.1),transparent)] pointer-events-none" />
      
      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-4xl font-bold bg-gradient-to-r from-indigo-400 to-purple-500 bg-clip-text text-transparent mb-2">
              🔍 Forensics & Audit Trail
            </h1>
            <p className="text-gray-300">Digital forensics, evidence management, and comprehensive audit logging</p>
          </div>
          
          <div className="flex items-center space-x-4">
            <div className={`flex items-center space-x-2 px-4 py-2 rounded-lg ${
              isMonitoring ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
            }`}>
              <div className={`w-2 h-2 rounded-full ${isMonitoring ? 'bg-green-400 animate-pulse' : 'bg-gray-400'}`} />
              <span className="text-sm font-medium">
                {isMonitoring ? 'MONITORING ACTIVE' : 'MONITORING PAUSED'}
              </span>
            </div>
            
            <button
              onClick={() => setIsMonitoring(!isMonitoring)}
              className={`px-4 py-2 rounded-lg font-medium transition-colors flex items-center space-x-2 ${
                isMonitoring 
                  ? 'bg-red-500/20 hover:bg-red-500/30 text-red-400' 
                  : 'bg-green-500/20 hover:bg-green-500/30 text-green-400'
              }`}
            >
              {isMonitoring ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
              <span>{isMonitoring ? 'Pause' : 'Resume'}</span>
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-2 mb-8">
          <div className="flex space-x-2">
            {[
              { id: 'dashboard', label: '📊 Dashboard', icon: BarChart3 },
              { id: 'cases', label: '🔍 Cases', icon: Search },
              { id: 'evidence', label: '📁 Evidence', icon: Database },
              { id: 'audit', label: '📋 Audit Logs', icon: FileText },
              { id: 'timeline', label: '⏱️ Timeline', icon: Clock },
              { id: 'compliance', label: '✅ Compliance', icon: CheckCircle }
            ].map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex-1 px-4 py-3 rounded-xl font-medium transition-all duration-200 flex items-center justify-center space-x-2 ${
                    activeTab === tab.id
                      ? 'bg-indigo-500/20 text-indigo-400 border border-indigo-500/30'
                      : 'text-gray-400 hover:text-white hover:bg-gray-700/30'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span className="hidden sm:inline">{tab.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Dashboard Tab */}
        {activeTab === 'dashboard' && dashboard && (
          <div className="space-y-8">
            {/* Key Metrics */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="bg-blue-500/10 border border-blue-500/20 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <Search className="w-8 h-8 text-blue-400" />
                  <div className="text-right">
                    <div className="text-2xl font-bold text-white">{dashboard.activeCases}</div>
                    <div className="text-sm text-blue-400">Active Cases</div>
                  </div>
                </div>
                <div className="text-xs text-gray-400">Ongoing investigations</div>
              </div>

              <div className="bg-purple-500/10 border border-purple-500/20 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <Database className="w-8 h-8 text-purple-400" />
                  <div className="text-right">
                    <div className="text-2xl font-bold text-white">{dashboard.evidenceItems}</div>
                    <div className="text-sm text-purple-400">Evidence Items</div>
                  </div>
                </div>
                <div className="text-xs text-gray-400">Collected and preserved</div>
              </div>

              <div className="bg-orange-500/10 border border-orange-500/20 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <Clock className="w-8 h-8 text-orange-400" />
                  <div className="text-right">
                    <div className="text-2xl font-bold text-white">{dashboard.pendingAnalysis}</div>
                    <div className="text-sm text-orange-400">Pending Analysis</div>
                  </div>
                </div>
                <div className="text-xs text-gray-400">Awaiting examination</div>
              </div>

              <div className="bg-green-500/10 border border-green-500/20 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <CheckCircle className="w-8 h-8 text-green-400" />
                  <div className="text-right">
                    <div className="text-2xl font-bold text-white">{dashboard.complianceScore}%</div>
                    <div className="text-sm text-green-400">Compliance</div>
                  </div>
                </div>
                <div className="text-xs text-gray-400">Audit compliance score</div>
              </div>
            </div>

            {/* Risk Metrics */}
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-6 flex items-center">
                <AlertTriangle className="w-5 h-5 mr-3 text-red-400" />
                Security Risk Metrics
              </h3>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-6">
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-400 mb-1">{dashboard.riskMetrics.highRiskEvents}</div>
                  <div className="text-sm text-gray-400">High Risk Events</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-orange-400 mb-1">{dashboard.riskMetrics.failedLogins}</div>
                  <div className="text-sm text-gray-400">Failed Logins</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-yellow-400 mb-1">{dashboard.riskMetrics.privilegedAccess}</div>
                  <div className="text-sm text-gray-400">Privileged Access</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-purple-400 mb-1">{dashboard.riskMetrics.dataExfiltration}</div>
                  <div className="text-sm text-gray-400">Data Exfiltration</div>
                </div>
              </div>
            </div>

            {/* Charts */}
            <div className="grid lg:grid-cols-2 gap-8">
              {/* Cases by Status */}
              <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
                <h3 className="text-xl font-bold text-white mb-6">Cases by Status</h3>
                <div className="space-y-4">
                  {Object.entries(dashboard.casesByStatus).map(([status, count], index) => (
                    <div key={status} className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className={`w-3 h-3 rounded-full ${
                          index === 0 ? 'bg-blue-400' :
                          index === 1 ? 'bg-yellow-400' :
                          index === 2 ? 'bg-purple-400' :
                          index === 3 ? 'bg-orange-400' : 'bg-green-400'
                        }`} />
                        <span className="text-gray-300 capitalize">{status}</span>
                      </div>
                      <span className="text-white font-bold">{count}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Evidence by Type */}
              <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
                <h3 className="text-xl font-bold text-white mb-6">Evidence by Type</h3>
                <div className="space-y-4">
                  {Object.entries(dashboard.evidenceByType).map(([type, count], index) => (
                    <div key={type} className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <span className="text-lg">{getEvidenceTypeIcon(type)}</span>
                        <span className="text-gray-300">{type.replace('_', ' ')}</span>
                      </div>
                      <span className="text-white font-bold">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Recent Activity */}
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-6 flex items-center">
                <Activity className="w-5 h-5 mr-3 text-green-400" />
                Recent Forensic Activity
              </h3>
              <div className="space-y-4">
                {dashboard.recentActivity.slice(0, 5).map((activity) => (
                  <div key={activity.id} className="flex items-center justify-between p-4 bg-black/30 rounded-xl border border-gray-700/50">
                    <div className="flex items-center space-x-4">
                      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                        activity.riskScore >= 80 ? 'bg-red-500/20' :
                        activity.riskScore >= 60 ? 'bg-orange-500/20' :
                        activity.riskScore >= 40 ? 'bg-yellow-500/20' : 'bg-green-500/20'
                      }`}>
                        {activity.eventType === 'evidence_access' ? '📁' :
                         activity.eventType === 'authentication' ? '🔐' :
                         activity.eventType === 'data_access' ? '📊' : '⚡'}
                      </div>
                      <div>
                        <div className="text-white font-medium">{activity.action.replace('_', ' ')}</div>
                        <div className="text-gray-400 text-sm">
                          {activity.userName} • {activity.timestamp.toLocaleTimeString()}
                        </div>
                      </div>
                    </div>
                    <div className={`px-3 py-1 rounded-full text-xs font-medium ${
                      activity.riskScore >= 80 ? 'bg-red-500/20 text-red-400' :
                      activity.riskScore >= 60 ? 'bg-orange-500/20 text-orange-400' :
                      activity.riskScore >= 40 ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-green-500/20 text-green-400'
                    }`}>
                      Risk: {activity.riskScore}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Cases Tab */}
        {activeTab === 'cases' && (
          <div className="space-y-6">
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-bold text-white">Forensic Cases</h3>
                <button className="px-4 py-2 bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-400 rounded-lg transition-colors">
                  Create New Case
                </button>
              </div>
              
              <div className="space-y-4">
                {cases.map((case_) => (
                  <div
                    key={case_.id}
                    className="bg-black/30 border border-gray-700/50 rounded-xl p-6 cursor-pointer transition-all duration-200 hover:scale-[1.02]"
                    onClick={() => setSelectedCase(case_)}
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <h4 className="text-lg font-bold text-white mb-2">{case_.title}</h4>
                        <p className="text-gray-300 mb-2">{case_.description}</p>
                        <div className="flex items-center space-x-4 text-sm text-gray-400">
                          <span>Case: {case_.caseNumber}</span>
                          <span>Investigator: {case_.investigator}</span>
                          <span>Created: {case_.createdAt.toLocaleDateString()}</span>
                        </div>
                      </div>
                      
                      <div className="flex items-center space-x-3">
                        <span className={`px-3 py-1 rounded border text-sm font-medium ${getPriorityColor(case_.priority)}`}>
                          {case_.priority.toUpperCase()}
                        </span>
                        <span className={`px-3 py-1 rounded border text-sm font-medium ${getStatusColor(case_.status)}`}>
                          {case_.status.toUpperCase()}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between">
                      <div className="flex space-x-4 text-sm text-gray-400">
                        <span>Evidence: {case_.evidence.length}</span>
                        <span>Timeline: {case_.timeline.length}</span>
                        <span>Findings: {case_.findings.length}</span>
                        {case_.legalHold && <span className="text-red-400">🔒 Legal Hold</span>}
                      </div>
                      
                      <div className="flex space-x-2">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            generateCaseReport(case_);
                          }}
                          className="px-3 py-1 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded text-xs transition-colors flex items-center space-x-1"
                        >
                          <Download className="w-3 h-3" />
                          <span>Report</span>
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedCase(case_);
                          }}
                          className="px-3 py-1 bg-green-500/20 hover:bg-green-500/30 text-green-400 rounded text-xs transition-colors flex items-center space-x-1"
                        >
                          <Eye className="w-3 h-3" />
                          <span>Details</span>
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Evidence Tab */}
        {activeTab === 'evidence' && (
          <div className="space-y-6">
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-bold text-white">Digital Evidence</h3>
                <button className="px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 text-purple-400 rounded-lg transition-colors">
                  Add Evidence
                </button>
              </div>
              
              <div className="space-y-4">
                {evidence.map((item) => (
                  <div
                    key={item.id}
                    className="bg-black/30 border border-gray-700/50 rounded-xl p-6 cursor-pointer transition-all duration-200 hover:scale-[1.02]"
                    onClick={() => setSelectedEvidence(item)}
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center space-x-4">
                        <div className="text-3xl">{getEvidenceTypeIcon(item.type)}</div>
                        <div>
                          <h4 className="text-lg font-bold text-white mb-1">{item.description}</h4>
                          <div className="flex items-center space-x-4 text-sm text-gray-400">
                            <span>Evidence: {item.evidenceNumber}</span>
                            <span>Source: {item.source}</span>
                            <span>Size: {formatFileSize(item.size)}</span>
                          </div>
                        </div>
                      </div>
                      
                      <div className="flex items-center space-x-3">
                        {item.verified && <CheckCircle className="w-5 h-5 text-green-400" />}
                        {item.encrypted && <Lock className="w-5 h-5 text-blue-400" />}
                        {item.legalHold && <span className="text-red-400 text-sm">🔒 Legal Hold</span>}
                      </div>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                      <div>
                        <span className="text-gray-400 text-sm">Collected By:</span>
                        <div className="text-white">{item.collectedBy}</div>
                      </div>
                      <div>
                        <span className="text-gray-400 text-sm">Collection Date:</span>
                        <div className="text-white">{item.collectedAt.toLocaleDateString()}</div>
                      </div>
                      <div>
                        <span className="text-gray-400 text-sm">Tool:</span>
                        <div className="text-white">{item.acquisitionTool}</div>
                      </div>
                      <div>
                        <span className="text-gray-400 text-sm">Hash (SHA256):</span>
                        <div className="text-white font-mono text-xs">{item.hash.sha256.substring(0, 16)}...</div>
                      </div>
                    </div>

                    <div className="flex items-center justify-between">
                      <div className="flex space-x-4 text-sm text-gray-400">
                        <span>Chain of Custody: {item.chainOfCustody.length} entries</span>
                        <span>Analysis: {item.analysis.length} completed</span>
                        <span>Access Log: {item.accessLog.length} entries</span>
                      </div>
                      
                      <div className="flex space-x-2">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            // Handle evidence analysis
                          }}
                          className="px-3 py-1 bg-purple-500/20 hover:bg-purple-500/30 text-purple-400 rounded text-xs transition-colors"
                        >
                          Analyze
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEvidence(item);
                          }}
                          className="px-3 py-1 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded text-xs transition-colors flex items-center space-x-1"
                        >
                          <Eye className="w-3 h-3" />
                          <span>Details</span>
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Audit Logs Tab */}
        {activeTab === 'audit' && (
          <div className="space-y-6">
            {/* Filters */}
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-bold text-white">Filter Audit Logs</h3>
                <div className="flex space-x-4">
                  <select
                    value={timeRange}
                    onChange={(e) => setTimeRange(e.target.value as any)}
                    className="px-4 py-2 bg-black/50 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
                  >
                    <option value="1h">Last Hour</option>
                    <option value="24h">Last 24 Hours</option>
                    <option value="7d">Last 7 Days</option>
                    <option value="30d">Last 30 Days</option>
                  </select>
                  
                  <select
                    value={filter}
                    onChange={(e) => setFilter(e.target.value as any)}
                    className="px-4 py-2 bg-black/50 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
                  >
                    <option value="all">All Risk Levels</option>
                    <option value="critical">Critical (90+)</option>
                    <option value="high">High (70-89)</option>
                    <option value="medium">Medium (40-69)</option>
                    <option value="low">Low (0-39)</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Audit Logs */}
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-6">System Audit Trail</h3>
              
              <div className="space-y-4">
                {filteredAuditLogs.length === 0 ? (
                  <div className="text-center py-8">
                    <FileText className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                    <p className="text-gray-400">No audit logs found matching current filters</p>
                  </div>
                ) : (
                  filteredAuditLogs.map((log) => (
                    <div key={log.id} className="bg-black/30 border border-gray-700/50 rounded-xl p-6">
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex items-center space-x-4">
                          <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                            log.riskScore >= 80 ? 'bg-red-500/20' :
                            log.riskScore >= 60 ? 'bg-orange-500/20' :
                            log.riskScore >= 40 ? 'bg-yellow-500/20' : 'bg-green-500/20'
                          }`}>
                            {log.eventType === 'evidence_access' ? '📁' :
                             log.eventType === 'authentication' ? '🔐' :
                             log.eventType === 'data_access' ? '📊' :
                             log.eventType === 'system_change' ? '⚙️' : '⚡'}
                          </div>
                          <div>
                            <h4 className="text-lg font-bold text-white mb-1">{log.action.replace('_', ' ')}</h4>
                            <div className="flex items-center space-x-4 text-sm text-gray-400">
                              <span>User: {log.userName}</span>
                              <span>IP: {log.sourceIP}</span>
                              <span>{log.timestamp.toLocaleString()}</span>
                            </div>
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-3">
                          <span className={`px-3 py-1 rounded text-sm font-medium ${
                            log.outcome === 'success' ? 'bg-green-500/20 text-green-400' :
                            log.outcome === 'failure' ? 'bg-red-500/20 text-red-400' :
                            'bg-yellow-500/20 text-yellow-400'
                          }`}>
                            {log.outcome.toUpperCase()}
                          </span>
                          <span className={`px-3 py-1 rounded text-sm font-medium ${
                            log.riskScore >= 80 ? 'bg-red-500/20 text-red-400' :
                            log.riskScore >= 60 ? 'bg-orange-500/20 text-orange-400' :
                            log.riskScore >= 40 ? 'bg-yellow-500/20 text-yellow-400' :
                            'bg-green-500/20 text-green-400'
                          }`}>
                            Risk: {log.riskScore}
                          </span>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                        <div>
                          <span className="text-gray-400 text-sm">Resource:</span>
                          <div className="text-white">{log.resource}</div>
                        </div>
                        <div>
                          <span className="text-gray-400 text-sm">Event Type:</span>
                          <div className="text-white">{log.eventType.replace('_', ' ')}</div>
                        </div>
                        <div>
                          <span className="text-gray-400 text-sm">Session:</span>
                          <div className="text-white font-mono text-sm">{log.sessionId}</div>
                        </div>
                      </div>

                      {log.geolocation && (
                        <div className="text-sm text-gray-400">
                          Location: {log.geolocation.city}, {log.geolocation.region}, {log.geolocation.country}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {/* Timeline Tab */}
        {activeTab === 'timeline' && (
          <div className="space-y-6">
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-6 flex items-center">
                <Clock className="w-5 h-5 mr-3 text-blue-400" />
                Forensic Timeline Reconstruction
              </h3>
              
              <div className="space-y-6">
                <div className="text-center py-8">
                  <Clock className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                  <p className="text-gray-400">Timeline reconstruction tools and visualizations</p>
                  <p className="text-gray-500 text-sm mt-2">Correlate events across multiple evidence sources</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Compliance Tab */}
        {activeTab === 'compliance' && (
          <div className="space-y-6">
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-6 flex items-center">
                <CheckCircle className="w-5 h-5 mr-3 text-green-400" />
                Compliance & Legal Requirements
              </h3>
              
              <div className="grid md:grid-cols-2 gap-6">
                <div className="bg-black/30 border border-gray-700/50 rounded-xl p-6">
                  <h4 className="text-lg font-bold text-white mb-4">Retention Policies</h4>
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">Evidence Retention</span>
                      <span className="text-green-400 font-bold">7 Years</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">Audit Log Retention</span>
                      <span className="text-green-400 font-bold">5 Years</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">Legal Hold Items</span>
                      <span className="text-yellow-400 font-bold">Indefinite</span>
                    </div>
                  </div>
                </div>
                
                <div className="bg-black/30 border border-gray-700/50 rounded-xl p-6">
                  <h4 className="text-lg font-bold text-white mb-4">Chain of Custody</h4>
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">Digital Signatures</span>
                      <span className="text-green-400 font-bold">✓ Enabled</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">Hash Verification</span>
                      <span className="text-green-400 font-bold">✓ Automated</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">Access Logging</span>
                      <span className="text-green-400 font-bold">✓ Complete</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Built with Bolt Badge */}
        <div className="mt-12 text-center">
          <div className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-blue-500/20 to-purple-500/20 border border-blue-500/30 rounded-xl">
            <Zap className="w-5 h-5 text-blue-400 mr-2" />
            <span className="text-blue-400 font-medium">Built with Bolt</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ForensicsAudit;