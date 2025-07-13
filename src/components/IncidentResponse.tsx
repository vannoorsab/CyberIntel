import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Play, FileText, Clock, CheckCircle, XCircle, Zap, Download, Eye, Settings, Users, Lock, Wifi, Server } from 'lucide-react';
import { useAlert } from '../contexts/AlertContext';
import { Incident, Playbook, ContainmentAction } from '../types';
import { IncidentResponseEngine } from '../utils/incidentResponse';

interface IncidentResponseProps {
  onNavigate: (page: string) => void;
}

const IncidentResponse: React.FC<IncidentResponseProps> = ({ onNavigate }) => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [isExecutingPlaybook, setIsExecutingPlaybook] = useState(false);
  const [filter, setFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'new' | 'investigating' | 'contained' | 'resolved'>('all');
  const { alerts } = useAlert();

  const irEngine = new IncidentResponseEngine();

  useEffect(() => {
    // Load mock incidents and playbooks
    loadMockData();
    
    // Auto-generate incidents from alerts
    const criticalAlerts = alerts.filter(alert => alert.priority === 'critical' && alert.status === 'unread');
    criticalAlerts.forEach(alert => {
      const existingIncident = incidents.find(inc => inc.relatedAlertId === alert.id);
      if (!existingIncident) {
        const newIncident = irEngine.createIncidentFromAlert(alert);
        setIncidents(prev => [newIncident, ...prev]);
      }
    });
  }, [alerts]);

  const loadMockData = () => {
    const mockIncidents: Incident[] = [
      {
        id: 'INC-001',
        title: 'Advanced Persistent Threat Detected',
        description: 'Multiple indicators suggest APT activity targeting financial data',
        severity: 'critical',
        status: 'investigating',
        priority: 1,
        assignedTo: 'SOC Team Alpha',
        createdAt: new Date(Date.now() - 3600000),
        updatedAt: new Date(Date.now() - 1800000),
        affectedSystems: ['web-server-01', 'database-02', 'workstation-15'],
        containmentActions: [
          { id: '1', type: 'isolate_endpoint', target: 'workstation-15', status: 'completed', timestamp: new Date() },
          { id: '2', type: 'block_ip', target: '203.0.113.42', status: 'completed', timestamp: new Date() }
        ],
        timeline: [
          { timestamp: new Date(Date.now() - 3600000), action: 'Incident created', user: 'System', details: 'Automated detection triggered' },
          { timestamp: new Date(Date.now() - 3000000), action: 'Assigned to SOC Team', user: 'Auto-Triage', details: 'High severity incident auto-assigned' },
          { timestamp: new Date(Date.now() - 1800000), action: 'Containment initiated', user: 'SOC Analyst', details: 'Endpoint isolation and IP blocking' }
        ],
        evidence: [
          { type: 'network_log', description: 'Suspicious outbound connections', path: '/logs/network/2024-01-20.log' },
          { type: 'file_hash', description: 'Malicious executable detected', path: 'SHA256: a1b2c3d4e5f6...' }
        ],
        relatedAlertId: 'alert_123'
      },
      {
        id: 'INC-002',
        title: 'Phishing Campaign Targeting Employees',
        description: 'Large-scale phishing emails detected with credential harvesting attempts',
        severity: 'high',
        status: 'contained',
        priority: 2,
        assignedTo: 'Security Team Beta',
        createdAt: new Date(Date.now() - 7200000),
        updatedAt: new Date(Date.now() - 3600000),
        affectedSystems: ['email-gateway', 'user-workstations'],
        containmentActions: [
          { id: '3', type: 'block_domain', target: 'phishing-site.com', status: 'completed', timestamp: new Date() },
          { id: '4', type: 'quarantine_emails', target: 'all_users', status: 'completed', timestamp: new Date() }
        ],
        timeline: [
          { timestamp: new Date(Date.now() - 7200000), action: 'Incident created', user: 'Email Security', details: 'Phishing detection triggered' },
          { timestamp: new Date(Date.now() - 6000000), action: 'Domain blocked', user: 'SOC Analyst', details: 'Malicious domain added to blocklist' },
          { timestamp: new Date(Date.now() - 3600000), action: 'Emails quarantined', user: 'Email Admin', details: 'All related emails quarantined' }
        ],
        evidence: [
          { type: 'email_headers', description: 'Phishing email samples', path: '/evidence/emails/phishing_samples.eml' },
          { type: 'url_analysis', description: 'Malicious URL analysis', path: '/evidence/urls/analysis_report.pdf' }
        ]
      }
    ];

    const mockPlaybooks: Playbook[] = [
      {
        id: 'PB-001',
        name: 'Malware Incident Response',
        description: 'Standard response for malware detection and containment',
        severity: ['high', 'critical'],
        steps: [
          { id: '1', name: 'Isolate Affected Systems', type: 'containment', automated: true, description: 'Automatically isolate infected endpoints' },
          { id: '2', name: 'Collect Evidence', type: 'investigation', automated: false, description: 'Gather forensic evidence from affected systems' },
          { id: '3', name: 'Analyze Malware', type: 'analysis', automated: true, description: 'Submit samples to sandbox for analysis' },
          { id: '4', name: 'Update Signatures', type: 'prevention', automated: true, description: 'Update AV signatures and IOCs' },
          { id: '5', name: 'Notify Stakeholders', type: 'communication', automated: true, description: 'Send notifications to relevant teams' }
        ],
        estimatedDuration: 120,
        lastUsed: new Date(Date.now() - 86400000)
      },
      {
        id: 'PB-002',
        name: 'Phishing Response',
        description: 'Response playbook for phishing attacks',
        severity: ['medium', 'high'],
        steps: [
          { id: '1', name: 'Block Malicious URLs', type: 'containment', automated: true, description: 'Add URLs to security appliance blocklist' },
          { id: '2', name: 'Quarantine Emails', type: 'containment', automated: true, description: 'Quarantine related emails from all mailboxes' },
          { id: '3', name: 'User Notification', type: 'communication', automated: true, description: 'Send security awareness notification' },
          { id: '4', name: 'Reset Compromised Accounts', type: 'remediation', automated: false, description: 'Reset passwords for affected users' }
        ],
        estimatedDuration: 60,
        lastUsed: new Date(Date.now() - 3600000)
      },
      {
        id: 'PB-003',
        name: 'Data Breach Response',
        description: 'Comprehensive response for data breach incidents',
        severity: ['critical'],
        steps: [
          { id: '1', name: 'Immediate Containment', type: 'containment', automated: true, description: 'Isolate affected systems and networks' },
          { id: '2', name: 'Legal Notification', type: 'communication', automated: false, description: 'Notify legal team and compliance officer' },
          { id: '3', name: 'Forensic Investigation', type: 'investigation', automated: false, description: 'Engage forensic team for detailed analysis' },
          { id: '4', name: 'Regulatory Reporting', type: 'compliance', automated: false, description: 'Prepare regulatory notifications if required' },
          { id: '5', name: 'Customer Communication', type: 'communication', automated: false, description: 'Prepare customer notification if needed' }
        ],
        estimatedDuration: 480,
        lastUsed: new Date(Date.now() - 604800000)
      }
    ];

    setIncidents(mockIncidents);
    setPlaybooks(mockPlaybooks);
  };

  const executePlaybook = async (incident: Incident, playbook: Playbook) => {
    setIsExecutingPlaybook(true);
    
    try {
      const result = await irEngine.executePlaybook(incident, playbook);
      
      // Update incident with playbook execution results
      setIncidents(prev => prev.map(inc => 
        inc.id === incident.id 
          ? { 
              ...inc, 
              status: 'investigating',
              containmentActions: [...inc.containmentActions, ...result.containmentActions],
              timeline: [...inc.timeline, ...result.timelineEntries]
            }
          : inc
      ));
      
      console.log('Playbook execution completed:', result);
    } catch (error) {
      console.error('Playbook execution failed:', error);
    } finally {
      setIsExecutingPlaybook(false);
    }
  };

  const generateIncidentReport = (incident: Incident) => {
    const report = irEngine.generateIncidentReport(incident);
    
    // Create and download the report
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incident_report_${incident.id}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
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
      case 'new': return 'text-red-400 bg-red-500/20 border-red-500/30';
      case 'investigating': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
      case 'contained': return 'text-blue-400 bg-blue-500/20 border-blue-500/30';
      case 'resolved': return 'text-green-400 bg-green-500/20 border-green-500/30';
      default: return 'text-gray-400 bg-gray-500/20 border-gray-500/30';
    }
  };

  const getContainmentIcon = (type: string) => {
    switch (type) {
      case 'isolate_endpoint': return <Server className="w-4 h-4" />;
      case 'block_ip': return <Shield className="w-4 h-4" />;
      case 'block_domain': return <Wifi className="w-4 h-4" />;
      case 'quarantine_emails': return <Lock className="w-4 h-4" />;
      default: return <Settings className="w-4 h-4" />;
    }
  };

  const filteredIncidents = incidents.filter(incident => {
    const severityMatch = filter === 'all' || incident.severity === filter;
    const statusMatch = statusFilter === 'all' || incident.status === statusFilter;
    return severityMatch && statusMatch;
  });

  const criticalIncidents = incidents.filter(inc => inc.severity === 'critical').length;
  const activeIncidents = incidents.filter(inc => inc.status !== 'resolved').length;

  return (
    <div className="min-h-screen bg-gradient-to-br from-black via-gray-900 to-black">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_70%,rgba(239,68,68,0.1),transparent)] pointer-events-none" />
      
      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold bg-gradient-to-r from-red-400 to-orange-500 bg-clip-text text-transparent mb-2">
            🚨 Incident Response Automation
          </h1>
          <p className="text-gray-300">Automated triage, containment, and response orchestration</p>
        </div>

        {/* Metrics Dashboard */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-red-500/10 border border-red-500/20 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <AlertTriangle className="w-8 h-8 text-red-400" />
              <div className="text-right">
                <div className="text-2xl font-bold text-white">{criticalIncidents}</div>
                <div className="text-sm text-red-400">Critical</div>
              </div>
            </div>
            <div className="text-xs text-gray-400">High priority incidents</div>
          </div>

          <div className="bg-orange-500/10 border border-orange-500/20 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <Clock className="w-8 h-8 text-orange-400" />
              <div className="text-right">
                <div className="text-2xl font-bold text-white">{activeIncidents}</div>
                <div className="text-sm text-orange-400">Active</div>
              </div>
            </div>
            <div className="text-xs text-gray-400">Ongoing incidents</div>
          </div>

          <div className="bg-blue-500/10 border border-blue-500/20 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <Play className="w-8 h-8 text-blue-400" />
              <div className="text-right">
                <div className="text-2xl font-bold text-white">{playbooks.length}</div>
                <div className="text-sm text-blue-400">Playbooks</div>
              </div>
            </div>
            <div className="text-xs text-gray-400">Available response playbooks</div>
          </div>

          <div className="bg-green-500/10 border border-green-500/20 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <CheckCircle className="w-8 h-8 text-green-400" />
              <div className="text-right">
                <div className="text-2xl font-bold text-white">
                  {incidents.filter(inc => inc.status === 'resolved').length}
                </div>
                <div className="text-sm text-green-400">Resolved</div>
              </div>
            </div>
            <div className="text-xs text-gray-400">Completed incidents</div>
          </div>
        </div>

        {/* Incident Management */}
        <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8 mb-8">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold text-white">Active Incidents</h2>
            
            <div className="flex space-x-4">
              <select
                value={filter}
                onChange={(e) => setFilter(e.target.value as any)}
                className="px-4 py-2 bg-black/50 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500/50"
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
                className="px-4 py-2 bg-black/50 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500/50"
              >
                <option value="all">All Statuses</option>
                <option value="new">New</option>
                <option value="investigating">Investigating</option>
                <option value="contained">Contained</option>
                <option value="resolved">Resolved</option>
              </select>
            </div>
          </div>

          <div className="space-y-4">
            {filteredIncidents.length === 0 ? (
              <div className="text-center py-8">
                <Shield className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                <p className="text-gray-400">No incidents found matching current filters</p>
              </div>
            ) : (
              filteredIncidents.map((incident) => (
                <div
                  key={incident.id}
                  className={`border rounded-xl p-6 cursor-pointer transition-all duration-200 hover:scale-[1.02] ${
                    getSeverityColor(incident.severity)
                  }`}
                  onClick={() => setSelectedIncident(incident)}
                >
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <div className="flex items-center space-x-3 mb-2">
                        <h3 className="text-lg font-bold text-white">{incident.title}</h3>
                        <span className={`px-2 py-1 rounded border text-xs font-medium ${getSeverityColor(incident.severity)}`}>
                          {incident.severity.toUpperCase()}
                        </span>
                        <span className={`px-2 py-1 rounded border text-xs font-medium ${getStatusColor(incident.status)}`}>
                          {incident.status.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-gray-300 mb-2">{incident.description}</p>
                      <div className="text-sm text-gray-400">
                        ID: {incident.id} • Assigned: {incident.assignedTo} • Priority: {incident.priority}
                      </div>
                    </div>
                    
                    <div className="text-right">
                      <div className="text-sm text-gray-400">
                        Created: {incident.createdAt.toLocaleString()}
                      </div>
                      <div className="text-sm text-gray-400">
                        Updated: {incident.updatedAt.toLocaleString()}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="flex space-x-4 text-sm">
                      <span className="text-gray-400">
                        Affected Systems: {incident.affectedSystems.length}
                      </span>
                      <span className="text-gray-400">
                        Containment Actions: {incident.containmentActions.length}
                      </span>
                    </div>
                    
                    <div className="flex space-x-2">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          generateIncidentReport(incident);
                        }}
                        className="px-3 py-1 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded text-xs transition-colors flex items-center space-x-1"
                      >
                        <Download className="w-3 h-3" />
                        <span>Report</span>
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedIncident(incident);
                        }}
                        className="px-3 py-1 bg-green-500/20 hover:bg-green-500/30 text-green-400 rounded text-xs transition-colors flex items-center space-x-1"
                      >
                        <Eye className="w-3 h-3" />
                        <span>Details</span>
                      </button>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Response Playbooks */}
        <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
          <h2 className="text-2xl font-bold text-white mb-6 flex items-center">
            <Play className="w-6 h-6 mr-3 text-blue-400" />
            Response Playbooks
          </h2>
          
          <div className="grid md:grid-cols-3 gap-6">
            {playbooks.map((playbook) => (
              <div key={playbook.id} className="bg-black/30 border border-gray-700/50 rounded-xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-bold text-white">{playbook.name}</h3>
                  <span className="text-sm text-gray-400">{playbook.estimatedDuration}min</span>
                </div>
                
                <p className="text-gray-300 text-sm mb-4">{playbook.description}</p>
                
                <div className="space-y-2 mb-4">
                  <div className="text-sm text-gray-400">
                    Severity: {playbook.severity.join(', ')}
                  </div>
                  <div className="text-sm text-gray-400">
                    Steps: {playbook.steps.length}
                  </div>
                  <div className="text-sm text-gray-400">
                    Last Used: {playbook.lastUsed.toLocaleDateString()}
                  </div>
                </div>
                
                <div className="space-y-2">
                  {playbook.steps.slice(0, 3).map((step) => (
                    <div key={step.id} className="flex items-center space-x-2 text-xs">
                      <div className={`w-2 h-2 rounded-full ${step.automated ? 'bg-green-400' : 'bg-yellow-400'}`} />
                      <span className="text-gray-300">{step.name}</span>
                    </div>
                  ))}
                  {playbook.steps.length > 3 && (
                    <div className="text-xs text-gray-400">
                      +{playbook.steps.length - 3} more steps
                    </div>
                  )}
                </div>
                
                {selectedIncident && (
                  <button
                    onClick={() => executePlaybook(selectedIncident, playbook)}
                    disabled={isExecutingPlaybook}
                    className="w-full mt-4 px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center space-x-2"
                  >
                    {isExecutingPlaybook ? (
                      <>
                        <div className="animate-spin rounded-full h-4 w-4 border-2 border-blue-400 border-t-transparent" />
                        <span>Executing...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4" />
                        <span>Execute</span>
                      </>
                    )}
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Incident Detail Modal */}
        {selectedIncident && (
          <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-gray-900 border border-gray-700 rounded-2xl p-8 max-w-6xl w-full max-h-[90vh] overflow-y-auto">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-2xl font-bold text-white">Incident Details: {selectedIncident.id}</h3>
                <button
                  onClick={() => setSelectedIncident(null)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  ✕
                </button>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Left Column */}
                <div className="space-y-6">
                  {/* Basic Info */}
                  <div>
                    <h4 className="text-lg font-bold text-white mb-4">Incident Information</h4>
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Title:</span>
                        <span className="text-white">{selectedIncident.title}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Severity:</span>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(selectedIncident.severity)}`}>
                          {selectedIncident.severity.toUpperCase()}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Status:</span>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(selectedIncident.status)}`}>
                          {selectedIncident.status.toUpperCase()}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Assigned To:</span>
                        <span className="text-white">{selectedIncident.assignedTo}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Priority:</span>
                        <span className="text-white">{selectedIncident.priority}</span>
                      </div>
                    </div>
                  </div>

                  {/* Affected Systems */}
                  <div>
                    <h4 className="text-lg font-bold text-white mb-4">Affected Systems</h4>
                    <div className="space-y-2">
                      {selectedIncident.affectedSystems.map((system, index) => (
                        <div key={index} className="bg-black/30 rounded-lg p-3 flex items-center space-x-3">
                          <Server className="w-4 h-4 text-blue-400" />
                          <span className="text-white font-mono text-sm">{system}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Containment Actions */}
                  <div>
                    <h4 className="text-lg font-bold text-white mb-4">Containment Actions</h4>
                    <div className="space-y-2">
                      {selectedIncident.containmentActions.map((action) => (
                        <div key={action.id} className="bg-black/30 rounded-lg p-3">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center space-x-2">
                              {getContainmentIcon(action.type)}
                              <span className="text-white text-sm font-medium">
                                {action.type.replace('_', ' ').toUpperCase()}
                              </span>
                            </div>
                            <span className={`px-2 py-1 rounded text-xs ${
                              action.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                              action.status === 'in_progress' ? 'bg-yellow-500/20 text-yellow-400' :
                              'bg-red-500/20 text-red-400'
                            }`}>
                              {action.status.toUpperCase()}
                            </span>
                          </div>
                          <div className="text-gray-400 text-sm">
                            Target: {action.target}
                          </div>
                          <div className="text-gray-400 text-xs">
                            {action.timestamp.toLocaleString()}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Right Column */}
                <div className="space-y-6">
                  {/* Timeline */}
                  <div>
                    <h4 className="text-lg font-bold text-white mb-4">Incident Timeline</h4>
                    <div className="space-y-3">
                      {selectedIncident.timeline.map((entry, index) => (
                        <div key={index} className="flex space-x-3">
                          <div className="flex-shrink-0 w-2 h-2 bg-blue-400 rounded-full mt-2" />
                          <div className="flex-1">
                            <div className="text-white text-sm font-medium">{entry.action}</div>
                            <div className="text-gray-400 text-xs">
                              {entry.user} • {entry.timestamp.toLocaleString()}
                            </div>
                            <div className="text-gray-300 text-xs mt-1">{entry.details}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Evidence */}
                  <div>
                    <h4 className="text-lg font-bold text-white mb-4">Evidence</h4>
                    <div className="space-y-2">
                      {selectedIncident.evidence.map((evidence, index) => (
                        <div key={index} className="bg-black/30 rounded-lg p-3">
                          <div className="flex items-center space-x-2 mb-1">
                            <FileText className="w-4 h-4 text-green-400" />
                            <span className="text-white text-sm font-medium">{evidence.type.toUpperCase()}</span>
                          </div>
                          <div className="text-gray-300 text-sm">{evidence.description}</div>
                          <div className="text-gray-400 text-xs font-mono">{evidence.path}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Actions */}
                  <div>
                    <h4 className="text-lg font-bold text-white mb-4">Actions</h4>
                    <div className="space-y-3">
                      <button
                        onClick={() => generateIncidentReport(selectedIncident)}
                        className="w-full px-4 py-3 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded-lg transition-colors flex items-center justify-center space-x-2"
                      >
                        <Download className="w-4 h-4" />
                        <span>Generate Report</span>
                      </button>
                      
                      <div className="grid grid-cols-2 gap-3">
                        {playbooks
                          .filter(pb => pb.severity.includes(selectedIncident.severity))
                          .slice(0, 2)
                          .map((playbook) => (
                            <button
                              key={playbook.id}
                              onClick={() => executePlaybook(selectedIncident, playbook)}
                              disabled={isExecutingPlaybook}
                              className="px-3 py-2 bg-green-500/20 hover:bg-green-500/30 text-green-400 rounded-lg transition-colors text-sm disabled:opacity-50 flex items-center justify-center space-x-1"
                            >
                              <Play className="w-3 h-3" />
                              <span>{playbook.name}</span>
                            </button>
                          ))
                        }
                      </div>
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

export default IncidentResponse;