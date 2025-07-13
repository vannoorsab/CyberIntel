import React, { useState, useEffect } from 'react';
import { Shield, Eye, Lock, AlertTriangle, FileText, Users, Database, Network, Zap, Search, Filter, Download, Settings, Play, Pause, CheckCircle, XCircle, Clock, TrendingUp, TrendingDown, BarChart3, PieChart, Activity } from 'lucide-react';
import { useAlert } from '../contexts/AlertContext';
import { DLPPolicy, DLPViolation, DLPDashboard, DataClassification, EncryptionPolicy, AccessControlPolicy, DataDiscovery } from '../types';
import { DLPEngine } from '../utils/dlpEngine';

interface DataLossPreventionProps {
  onNavigate: (page: string) => void;
}

const DataLossPrevention: React.FC<DataLossPreventionProps> = ({ onNavigate }) => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [policies, setPolicies] = useState<DLPPolicy[]>([]);
  const [violations, setViolations] = useState<DLPViolation[]>([]);
  const [dashboard, setDashboard] = useState<DLPDashboard | null>(null);
  const [dataClassifications, setDataClassifications] = useState<DataClassification[]>([]);
  const [encryptionPolicies, setEncryptionPolicies] = useState<EncryptionPolicy[]>([]);
  const [accessPolicies, setAccessPolicies] = useState<AccessControlPolicy[]>([]);
  const [dataDiscovery, setDataDiscovery] = useState<DataDiscovery[]>([]);
  const [selectedViolation, setSelectedViolation] = useState<DLPViolation | null>(null);
  const [filter, setFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'detected' | 'investigating' | 'confirmed' | 'resolved'>('all');
  const [isMonitoring, setIsMonitoring] = useState(true);
  const { addAlert } = useAlert();

  const dlpEngine = new DLPEngine();

  useEffect(() => {
    loadMockData();
    
    // Simulate real-time DLP monitoring
    if (isMonitoring) {
      const interval = setInterval(() => {
        simulateRealTimeViolations();
      }, 8000); // Check every 8 seconds

      return () => clearInterval(interval);
    }
  }, [isMonitoring]);

  const loadMockData = () => {
    // Mock DLP Policies
    const mockPolicies: DLPPolicy[] = [
      {
        id: 'DLP-001',
        name: 'PII Protection Policy',
        description: 'Prevent unauthorized transfer of personally identifiable information',
        enabled: true,
        priority: 1,
        dataTypes: [],
        conditions: [],
        actions: [],
        channels: [],
        exceptions: [],
        createdBy: 'Security Admin',
        createdAt: new Date(Date.now() - 86400000 * 30),
        lastModified: new Date(Date.now() - 86400000 * 7),
        violationCount: 45,
        falsePositiveRate: 12
      },
      {
        id: 'DLP-002',
        name: 'Financial Data Protection',
        description: 'Monitor and block unauthorized access to financial records',
        enabled: true,
        priority: 2,
        dataTypes: [],
        conditions: [],
        actions: [],
        channels: [],
        exceptions: [],
        createdBy: 'Compliance Officer',
        createdAt: new Date(Date.now() - 86400000 * 45),
        lastModified: new Date(Date.now() - 86400000 * 3),
        violationCount: 23,
        falsePositiveRate: 8
      },
      {
        id: 'DLP-003',
        name: 'Intellectual Property Shield',
        description: 'Protect proprietary code and trade secrets from exfiltration',
        enabled: true,
        priority: 3,
        dataTypes: [],
        conditions: [],
        actions: [],
        channels: [],
        exceptions: [],
        createdBy: 'CISO',
        createdAt: new Date(Date.now() - 86400000 * 60),
        lastModified: new Date(Date.now() - 86400000 * 1),
        violationCount: 12,
        falsePositiveRate: 15
      }
    ];

    // Mock Violations
    const mockViolations: DLPViolation[] = [
      {
        id: 'VIO-001',
        policyId: 'DLP-001',
        policyName: 'PII Protection Policy',
        severity: 'critical',
        status: 'detected',
        userId: 'user123',
        userEmail: 'john.doe@company.com',
        userName: 'John Doe',
        department: 'Marketing',
        timestamp: new Date(Date.now() - 1800000),
        channel: 'email',
        dataTypes: ['SSN', 'Credit Card'],
        matchedContent: [
          {
            dataType: 'SSN',
            pattern: 'XXX-XX-1234',
            confidence: 95,
            context: 'Customer database export containing SSN: XXX-XX-1234',
            location: 'email_attachment.csv',
            count: 1
          }
        ],
        destination: 'external@competitor.com',
        fileInfo: {
          fileName: 'customer_data.csv',
          fileType: 'CSV',
          fileSize: 2048576,
          filePath: '/exports/customer_data.csv',
          fileHash: 'sha256:abc123...',
          encrypted: false,
          owner: 'john.doe@company.com',
          lastModified: new Date()
        },
        actionTaken: ['blocked', 'quarantined', 'notified_admin'],
        falsePositive: false,
        riskScore: 95,
        evidence: []
      },
      {
        id: 'VIO-002',
        policyId: 'DLP-002',
        policyName: 'Financial Data Protection',
        severity: 'high',
        status: 'investigating',
        userId: 'user456',
        userEmail: 'jane.smith@company.com',
        userName: 'Jane Smith',
        department: 'Finance',
        timestamp: new Date(Date.now() - 3600000),
        channel: 'usb',
        dataTypes: ['Financial Records'],
        matchedContent: [
          {
            dataType: 'Financial Records',
            pattern: 'Account Balance',
            confidence: 87,
            context: 'Quarterly financial report with account balances',
            location: 'Q4_Report.xlsx',
            count: 15
          }
        ],
        actionTaken: ['logged', 'notified_user'],
        investigatedBy: 'Security Team',
        falsePositive: false,
        riskScore: 78,
        evidence: []
      }
    ];

    // Mock Dashboard Data
    const mockDashboard: DLPDashboard = {
      totalViolations: 156,
      criticalViolations: 23,
      violationsTrend: -12, // 12% decrease
      topDataTypes: [
        { type: 'PII', count: 45 },
        { type: 'Financial', count: 32 },
        { type: 'PHI', count: 28 },
        { type: 'IP', count: 18 }
      ],
      topUsers: [
        { user: 'john.doe@company.com', violations: 8 },
        { user: 'jane.smith@company.com', violations: 6 },
        { user: 'bob.wilson@company.com', violations: 5 }
      ],
      topChannels: [
        { channel: 'Email', count: 67 },
        { channel: 'USB', count: 34 },
        { channel: 'Cloud', count: 28 },
        { channel: 'Web', count: 27 }
      ],
      policyEffectiveness: [
        { policy: 'PII Protection', violations: 45, falsePositives: 5 },
        { policy: 'Financial Data', violations: 32, falsePositives: 3 },
        { policy: 'IP Shield', violations: 18, falsePositives: 2 }
      ],
      complianceScore: 87,
      encryptionCoverage: 73,
      recentViolations: mockViolations
    };

    // Mock Data Classifications
    const mockClassifications: DataClassification[] = [
      {
        id: 'CLASS-001',
        name: 'Social Security Numbers',
        type: 'pii',
        patterns: [
          {
            pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
            description: 'SSN format XXX-XX-XXXX',
            confidence: 95,
            examples: ['123-45-6789', '987-65-4321']
          }
        ],
        keywords: ['ssn', 'social security', 'social security number'],
        confidence: 95,
        sensitivity: 'restricted',
        description: 'US Social Security Numbers',
        examples: ['123-45-6789'],
        regulatoryFramework: ['PII', 'GDPR']
      },
      {
        id: 'CLASS-002',
        name: 'Credit Card Numbers',
        type: 'pci',
        patterns: [
          {
            pattern: '\\b(?:\\d{4}[- ]?){3}\\d{4}\\b',
            description: 'Credit card number format',
            confidence: 90,
            examples: ['4111-1111-1111-1111', '5555 5555 5555 4444']
          }
        ],
        keywords: ['credit card', 'card number', 'visa', 'mastercard'],
        confidence: 90,
        sensitivity: 'restricted',
        description: 'Credit card numbers',
        examples: ['4111-1111-1111-1111'],
        regulatoryFramework: ['PCI-DSS']
      }
    ];

    setPolicies(mockPolicies);
    setViolations(mockViolations);
    setDashboard(mockDashboard);
    setDataClassifications(mockClassifications);
  };

  const simulateRealTimeViolations = () => {
    if (Math.random() < 0.3) { // 30% chance of new violation
      const newViolation = dlpEngine.generateMockViolation();
      setViolations(prev => [newViolation, ...prev.slice(0, 49)]);

      // Auto-alert for critical violations
      if (newViolation.severity === 'critical') {
        addAlert({
          type: 'DLPViolation',
          userEmail: newViolation.userEmail,
          message: `🚨 Critical DLP violation: ${newViolation.policyName} by ${newViolation.userName}`,
          status: 'unread',
          relatedId: newViolation.id,
          priority: 'critical'
        });
      }

      // Update dashboard stats
      if (dashboard) {
        setDashboard(prev => prev ? {
          ...prev,
          totalViolations: prev.totalViolations + 1,
          criticalViolations: newViolation.severity === 'critical' ? prev.criticalViolations + 1 : prev.criticalViolations,
          recentViolations: [newViolation, ...prev.recentViolations.slice(0, 9)]
        } : null);
      }
    }
  };

  const handleViolationAction = (violationId: string, action: string) => {
    setViolations(prev => prev.map(violation => 
      violation.id === violationId 
        ? { ...violation, status: action as any, investigatedBy: 'Current Officer' }
        : violation
    ));
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/20 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/20 border-orange-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
      case 'low': return 'text-blue-400 bg-blue-500/20 border-blue-500/30';
      default: return 'text-gray-400 bg-gray-500/20 border-gray-500/30';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'detected': return 'text-red-400 bg-red-500/20 border-red-500/30';
      case 'investigating': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
      case 'confirmed': return 'text-orange-400 bg-orange-500/20 border-orange-500/30';
      case 'resolved': return 'text-green-400 bg-green-500/20 border-green-500/30';
      case 'false_positive': return 'text-blue-400 bg-blue-500/20 border-blue-500/30';
      default: return 'text-gray-400 bg-gray-500/20 border-gray-500/30';
    }
  };

  const getChannelIcon = (channel: string) => {
    switch (channel.toLowerCase()) {
      case 'email': return '📧';
      case 'usb': return '💾';
      case 'cloud': return '☁️';
      case 'web': return '🌐';
      case 'network': return '🔗';
      case 'endpoint': return '💻';
      case 'printer': return '🖨️';
      case 'mobile': return '📱';
      default: return '📄';
    }
  };

  const filteredViolations = violations.filter(violation => {
    const severityMatch = filter === 'all' || violation.severity === filter;
    const statusMatch = statusFilter === 'all' || violation.status === statusFilter;
    return severityMatch && statusMatch;
  });

  return (
    <div className="min-h-screen bg-gradient-to-br from-black via-gray-900 to-black">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_70%,rgba(59,130,246,0.1),transparent)] pointer-events-none" />
      
      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent mb-2">
              🛡️ Data Loss Prevention
            </h1>
            <p className="text-gray-300">Monitor, detect, and prevent unauthorized data transfers</p>
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
              { id: 'violations', label: '🚨 Violations', icon: AlertTriangle },
              { id: 'policies', label: '📋 Policies', icon: FileText },
              { id: 'encryption', label: '🔐 Encryption', icon: Lock },
              { id: 'discovery', label: '🔍 Data Discovery', icon: Search }
            ].map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex-1 px-6 py-3 rounded-xl font-medium transition-all duration-200 flex items-center justify-center space-x-2 ${
                    activeTab === tab.id
                      ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
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
              <div className="bg-red-500/10 border border-red-500/20 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <AlertTriangle className="w-8 h-8 text-red-400" />
                  <div className="text-right">
                    <div className="text-2xl font-bold text-white">{dashboard.totalViolations}</div>
                    <div className="text-sm text-red-400">Total Violations</div>
                  </div>
                </div>
                <div className="flex items-center text-xs">
                  {dashboard.violationsTrend < 0 ? (
                    <TrendingDown className="w-3 h-3 text-green-400 mr-1" />
                  ) : (
                    <TrendingUp className="w-3 h-3 text-red-400 mr-1" />
                  )}
                  <span className={dashboard.violationsTrend < 0 ? 'text-green-400' : 'text-red-400'}>
                    {Math.abs(dashboard.violationsTrend)}% this month
                  </span>
                </div>
              </div>

              <div className="bg-orange-500/10 border border-orange-500/20 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <Shield className="w-8 h-8 text-orange-400" />
                  <div className="text-right">
                    <div className="text-2xl font-bold text-white">{dashboard.criticalViolations}</div>
                    <div className="text-sm text-orange-400">Critical</div>
                  </div>
                </div>
                <div className="text-xs text-gray-400">Require immediate attention</div>
              </div>

              <div className="bg-green-500/10 border border-green-500/20 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <CheckCircle className="w-8 h-8 text-green-400" />
                  <div className="text-right">
                    <div className="text-2xl font-bold text-white">{dashboard.complianceScore}%</div>
                    <div className="text-sm text-green-400">Compliance</div>
                  </div>
                </div>
                <div className="text-xs text-gray-400">Overall compliance score</div>
              </div>

              <div className="bg-blue-500/10 border border-blue-500/20 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <Lock className="w-8 h-8 text-blue-400" />
                  <div className="text-right">
                    <div className="text-2xl font-bold text-white">{dashboard.encryptionCoverage}%</div>
                    <div className="text-sm text-blue-400">Encrypted</div>
                  </div>
                </div>
                <div className="text-xs text-gray-400">Data encryption coverage</div>
              </div>
            </div>

            {/* Charts and Analytics */}
            <div className="grid lg:grid-cols-2 gap-8">
              {/* Top Data Types */}
              <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
                <h3 className="text-xl font-bold text-white mb-6 flex items-center">
                  <PieChart className="w-5 h-5 mr-3 text-purple-400" />
                  Top Violated Data Types
                </h3>
                <div className="space-y-4">
                  {dashboard.topDataTypes.map((item, index) => (
                    <div key={index} className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className={`w-3 h-3 rounded-full ${
                          index === 0 ? 'bg-red-400' :
                          index === 1 ? 'bg-orange-400' :
                          index === 2 ? 'bg-yellow-400' : 'bg-blue-400'
                        }`} />
                        <span className="text-gray-300">{item.type}</span>
                      </div>
                      <span className="text-white font-bold">{item.count}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Top Channels */}
              <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
                <h3 className="text-xl font-bold text-white mb-6 flex items-center">
                  <Network className="w-5 h-5 mr-3 text-green-400" />
                  Violations by Channel
                </h3>
                <div className="space-y-4">
                  {dashboard.topChannels.map((item, index) => (
                    <div key={index} className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <span className="text-lg">{getChannelIcon(item.channel)}</span>
                        <span className="text-gray-300">{item.channel}</span>
                      </div>
                      <span className="text-white font-bold">{item.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Policy Effectiveness */}
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-6 flex items-center">
                <Activity className="w-5 h-5 mr-3 text-blue-400" />
                Policy Effectiveness
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-3 px-4 text-gray-300 font-medium">Policy</th>
                      <th className="text-left py-3 px-4 text-gray-300 font-medium">Violations</th>
                      <th className="text-left py-3 px-4 text-gray-300 font-medium">False Positives</th>
                      <th className="text-left py-3 px-4 text-gray-300 font-medium">Accuracy</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dashboard.policyEffectiveness.map((policy, index) => {
                      const accuracy = ((policy.violations - policy.falsePositives) / policy.violations * 100).toFixed(1);
                      return (
                        <tr key={index} className="border-b border-gray-800">
                          <td className="py-4 px-4 text-white">{policy.policy}</td>
                          <td className="py-4 px-4 text-orange-400">{policy.violations}</td>
                          <td className="py-4 px-4 text-red-400">{policy.falsePositives}</td>
                          <td className="py-4 px-4">
                            <span className={`px-2 py-1 rounded text-xs font-medium ${
                              parseFloat(accuracy) >= 90 ? 'bg-green-500/20 text-green-400' :
                              parseFloat(accuracy) >= 80 ? 'bg-yellow-500/20 text-yellow-400' :
                              'bg-red-500/20 text-red-400'
                            }`}>
                              {accuracy}%
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Violations Tab */}
        {activeTab === 'violations' && (
          <div className="space-y-6">
            {/* Filters */}
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-bold text-white">Filter Violations</h3>
                <div className="flex space-x-4">
                  <select
                    value={filter}
                    onChange={(e) => setFilter(e.target.value as any)}
                    className="px-4 py-2 bg-black/50 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  
                  <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value as any)}
                    className="px-4 py-2 bg-black/50 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                  >
                    <option value="all">All Statuses</option>
                    <option value="detected">Detected</option>
                    <option value="investigating">Investigating</option>
                    <option value="confirmed">Confirmed</option>
                    <option value="resolved">Resolved</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Violations List */}
            <div className="space-y-4">
              {filteredViolations.length === 0 ? (
                <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8 text-center">
                  <Shield className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                  <p className="text-gray-400">No violations found matching current filters</p>
                </div>
              ) : (
                filteredViolations.map((violation) => (
                  <div
                    key={violation.id}
                    className={`bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-6 cursor-pointer transition-all duration-200 hover:scale-[1.02] ${
                      violation.severity === 'critical' ? 'ring-2 ring-red-500/30' : ''
                    }`}
                    onClick={() => setSelectedViolation(violation)}
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center space-x-4">
                        <div className="text-2xl">{getChannelIcon(violation.channel)}</div>
                        <div>
                          <h4 className="text-lg font-bold text-white mb-1">{violation.policyName}</h4>
                          <div className="flex items-center space-x-4 text-sm text-gray-400">
                            <span>User: {violation.userName}</span>
                            <span>Department: {violation.department}</span>
                            <span>{violation.timestamp.toLocaleString()}</span>
                          </div>
                        </div>
                      </div>
                      
                      <div className="flex items-center space-x-3">
                        <span className={`px-3 py-1 rounded border text-sm font-medium ${getSeverityColor(violation.severity)}`}>
                          {violation.severity.toUpperCase()}
                        </span>
                        <span className={`px-3 py-1 rounded border text-sm font-medium ${getStatusColor(violation.status)}`}>
                          {violation.status.toUpperCase()}
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                      <div>
                        <span className="text-gray-400 text-sm">Data Types:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {violation.dataTypes.map((type, index) => (
                            <span key={index} className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded text-xs">
                              {type}
                            </span>
                          ))}
                        </div>
                      </div>
                      
                      <div>
                        <span className="text-gray-400 text-sm">Risk Score:</span>
                        <div className="mt-1">
                          <span className={`text-lg font-bold ${
                            violation.riskScore >= 90 ? 'text-red-400' :
                            violation.riskScore >= 70 ? 'text-orange-400' :
                            violation.riskScore >= 50 ? 'text-yellow-400' : 'text-green-400'
                          }`}>
                            {violation.riskScore}/100
                          </span>
                        </div>
                      </div>
                      
                      <div>
                        <span className="text-gray-400 text-sm">Actions Taken:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {violation.actionTaken.map((action, index) => (
                            <span key={index} className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-xs">
                              {action}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>

                    {violation.status === 'detected' && (
                      <div className="flex space-x-3">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleViolationAction(violation.id, 'investigating');
                          }}
                          className="px-4 py-2 bg-yellow-500/20 hover:bg-yellow-500/30 text-yellow-400 rounded-lg transition-colors text-sm"
                        >
                          Investigate
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleViolationAction(violation.id, 'false_positive');
                          }}
                          className="px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded-lg transition-colors text-sm"
                        >
                          Mark False Positive
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleViolationAction(violation.id, 'confirmed');
                          }}
                          className="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-400 rounded-lg transition-colors text-sm"
                        >
                          Confirm Violation
                        </button>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* Policies Tab */}
        {activeTab === 'policies' && (
          <div className="space-y-6">
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-bold text-white">DLP Policies</h3>
                <button className="px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded-lg transition-colors">
                  Create New Policy
                </button>
              </div>
              
              <div className="space-y-4">
                {policies.map((policy) => (
                  <div key={policy.id} className="bg-black/30 border border-gray-700/50 rounded-xl p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <h4 className="text-lg font-bold text-white mb-2">{policy.name}</h4>
                        <p className="text-gray-300 mb-2">{policy.description}</p>
                        <div className="flex items-center space-x-4 text-sm text-gray-400">
                          <span>Priority: {policy.priority}</span>
                          <span>Violations: {policy.violationCount}</span>
                          <span>False Positives: {policy.falsePositiveRate}%</span>
                        </div>
                      </div>
                      
                      <div className="flex items-center space-x-3">
                        <span className={`px-3 py-1 rounded text-sm font-medium ${
                          policy.enabled 
                            ? 'bg-green-500/20 text-green-400 border border-green-500/30' 
                            : 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
                        }`}>
                          {policy.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                        <button className="p-2 text-gray-400 hover:text-white transition-colors">
                          <Settings className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                    
                    <div className="text-xs text-gray-400">
                      Created by {policy.createdBy} • Last modified {policy.lastModified.toLocaleDateString()}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Encryption Tab */}
        {activeTab === 'encryption' && (
          <div className="space-y-6">
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-6 flex items-center">
                <Lock className="w-5 h-5 mr-3 text-green-400" />
                Encryption Management
              </h3>
              
              <div className="grid md:grid-cols-2 gap-6">
                <div className="bg-black/30 border border-gray-700/50 rounded-xl p-6">
                  <h4 className="text-lg font-bold text-white mb-4">Encryption Coverage</h4>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">Files at Rest</span>
                      <span className="text-green-400 font-bold">85%</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">Data in Transit</span>
                      <span className="text-green-400 font-bold">92%</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">Database Encryption</span>
                      <span className="text-yellow-400 font-bold">67%</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">Email Encryption</span>
                      <span className="text-green-400 font-bold">78%</span>
                    </div>
                  </div>
                </div>
                
                <div className="bg-black/30 border border-gray-700/50 rounded-xl p-6">
                  <h4 className="text-lg font-bold text-white mb-4">Key Management</h4>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-300">Active Keys</span>
                      <span className="text-white font-bold">1,247</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-300">Expiring Soon</span>
                      <span className="text-orange-400 font-bold">23</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-300">Rotation Schedule</span>
                      <span className="text-green-400 font-bold">On Track</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Data Discovery Tab */}
        {activeTab === 'discovery' && (
          <div className="space-y-6">
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-bold text-white flex items-center">
                  <Search className="w-5 h-5 mr-3 text-purple-400" />
                  Data Discovery & Classification
                </h3>
                <button className="px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 text-purple-400 rounded-lg transition-colors">
                  Start New Scan
                </button>
              </div>
              
              <div className="grid md:grid-cols-3 gap-6 mb-8">
                <div className="bg-black/30 border border-gray-700/50 rounded-xl p-6 text-center">
                  <Database className="w-8 h-8 text-blue-400 mx-auto mb-3" />
                  <div className="text-2xl font-bold text-white mb-1">2.4TB</div>
                  <div className="text-sm text-gray-400">Data Scanned</div>
                </div>
                
                <div className="bg-black/30 border border-gray-700/50 rounded-xl p-6 text-center">
                  <Eye className="w-8 h-8 text-purple-400 mx-auto mb-3" />
                  <div className="text-2xl font-bold text-white mb-1">15,847</div>
                  <div className="text-sm text-gray-400">Sensitive Files</div>
                </div>
                
                <div className="bg-black/30 border border-gray-700/50 rounded-xl p-6 text-center">
                  <Shield className="w-8 h-8 text-red-400 mx-auto mb-3" />
                  <div className="text-2xl font-bold text-white mb-1">3,291</div>
                  <div className="text-sm text-gray-400">Unprotected</div>
                </div>
              </div>
              
              <div className="bg-black/30 border border-gray-700/50 rounded-xl p-6">
                <h4 className="text-lg font-bold text-white mb-4">Recent Discovery Results</h4>
                <div className="space-y-3">
                  {[
                    { location: '/shared/finance/reports/', type: 'Financial Records', count: 156, risk: 'high' },
                    { location: '/hr/employee_data/', type: 'PII', count: 89, risk: 'critical' },
                    { location: '/marketing/customer_lists/', type: 'Customer Data', count: 234, risk: 'medium' },
                    { location: '/legal/contracts/', type: 'Legal Documents', count: 67, risk: 'low' }
                  ].map((item, index) => (
                    <div key={index} className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg">
                      <div className="flex items-center space-x-3">
                        <FileText className="w-4 h-4 text-gray-400" />
                        <div>
                          <div className="text-white font-medium">{item.location}</div>
                          <div className="text-gray-400 text-sm">{item.type} • {item.count} files</div>
                        </div>
                      </div>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        item.risk === 'critical' ? 'bg-red-500/20 text-red-400' :
                        item.risk === 'high' ? 'bg-orange-500/20 text-orange-400' :
                        item.risk === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-green-500/20 text-green-400'
                      }`}>
                        {item.risk.toUpperCase()}
                      </span>
                    </div>
                  ))}
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

export default DataLossPrevention;