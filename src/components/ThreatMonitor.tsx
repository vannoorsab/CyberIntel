import React, { useState, useEffect, useRef } from 'react';
import { Shield, Activity, AlertTriangle, TrendingUp, Eye, Zap, RefreshCw, Database, Network, Server, Cpu, HardDrive, Wifi, Globe, Map as MapIcon, BarChart3, Filter, Search, Calendar, Download, Settings, Play, Pause, Maximize2 } from 'lucide-react';
import { useAlert } from '../contexts/AlertContext';
import { createThreatAlert } from '../utils/alertUtils';

interface ThreatMonitorProps {
  onNavigate: (page: string) => void;
}

interface ThreatEvent {
  id: string;
  timestamp: Date;
  type: 'network' | 'endpoint' | 'malware' | 'anomaly' | 'intelligence';
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  sourceIP: string;
  targetIP?: string;
  country: string;
  city: string;
  latitude: number;
  longitude: number;
  description: string;
  details: any;
  status: 'active' | 'investigating' | 'resolved';
  attackVector: string;
  mitreTactic: string;
  assetType: string;
  confidence: number;
}

interface SystemMetrics {
  networkTraffic: number;
  endpointAlerts: number;
  malwareDetections: number;
  anomalies: number;
  threatIntelHits: number;
}

interface HeatmapData {
  country: string;
  threatCount: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  coordinates: [number, number];
}

interface AttackPath {
  id: string;
  source: string;
  target: string;
  technique: string;
  severity: string;
  timestamp: Date;
}

const ThreatMonitor: React.FC<ThreatMonitorProps> = ({ onNavigate }) => {
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [metrics, setMetrics] = useState<SystemMetrics>({
    networkTraffic: 0,
    endpointAlerts: 0,
    malwareDetections: 0,
    anomalies: 0,
    threatIntelHits: 0
  });
  const [isMonitoring, setIsMonitoring] = useState(true);
  const [selectedThreat, setSelectedThreat] = useState<ThreatEvent | null>(null);
  const [activeView, setActiveView] = useState<'overview' | 'heatmap' | 'attack-graph' | 'geolocation'>('overview');
  const [heatmapData, setHeatmapData] = useState<HeatmapData[]>([]);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  
  // Filters
  const [filters, setFilters] = useState({
    severity: 'all',
    type: 'all',
    country: 'all',
    assetType: 'all',
    timeRange: '24h',
    status: 'all'
  });

  const mapRef = useRef<HTMLDivElement>(null);
  const { addAlert } = useAlert();

  // Mock geolocation data for threats
  const mockLocations = [
    { country: 'Russia', city: 'Moscow', lat: 55.7558, lng: 37.6176 },
    { country: 'China', city: 'Beijing', lat: 39.9042, lng: 116.4074 },
    { country: 'North Korea', city: 'Pyongyang', lat: 39.0392, lng: 125.7625 },
    { country: 'Iran', city: 'Tehran', lat: 35.6892, lng: 51.3890 },
    { country: 'United States', city: 'New York', lat: 40.7128, lng: -74.0060 },
    { country: 'Germany', city: 'Berlin', lat: 52.5200, lng: 13.4050 },
    { country: 'Brazil', city: 'São Paulo', lat: -23.5505, lng: -46.6333 },
    { country: 'India', city: 'Mumbai', lat: 19.0760, lng: 72.8777 },
    { country: 'Nigeria', city: 'Lagos', lat: 6.5244, lng: 3.3792 },
    { country: 'Romania', city: 'Bucharest', lat: 44.4268, lng: 26.1025 }
  ];

  useEffect(() => {
    loadInitialData();
    
    if (isMonitoring) {
      const interval = setInterval(() => {
        simulateRealTimeThreats();
        updateHeatmapData();
        updateAttackPaths();
      }, 3000);

      return () => clearInterval(interval);
    }
  }, [isMonitoring]);

  const loadInitialData = () => {
    // Generate initial threat data
    const initialThreats = Array.from({ length: 50 }, () => generateMockThreat());
    setThreats(initialThreats);
    
    // Generate initial heatmap data
    updateHeatmapData();
    
    // Generate initial attack paths
    updateAttackPaths();
  };

  const generateMockThreat = (): ThreatEvent => {
    const location = mockLocations[Math.floor(Math.random() * mockLocations.length)];
    const threatTypes = ['network', 'endpoint', 'malware', 'anomaly', 'intelligence'] as const;
    const severities = ['low', 'medium', 'high', 'critical'] as const;
    const attackVectors = ['Email', 'Web', 'Network', 'USB', 'Remote', 'Social Engineering'];
    const mitreTactics = ['Initial Access', 'Execution', 'Persistence', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration'];
    const assetTypes = ['Server', 'Workstation', 'Network Device', 'Database', 'Web Application', 'Mobile Device'];
    
    const descriptions = [
      'Suspicious network traffic detected from external IP',
      'Malware signature match in downloaded file',
      'Anomalous login pattern detected',
      'Command and control communication identified',
      'Privilege escalation attempt blocked',
      'Data exfiltration pattern detected',
      'Brute force attack in progress',
      'Suspicious DNS queries to known bad domains',
      'Unauthorized file access attempt',
      'Potential insider threat activity',
      'Ransomware behavior pattern detected',
      'Phishing email with malicious attachment',
      'SQL injection attempt blocked',
      'Cross-site scripting attack detected',
      'DDoS attack pattern identified'
    ];

    return {
      id: `threat_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(Date.now() - Math.random() * 86400000), // Last 24 hours
      type: threatTypes[Math.floor(Math.random() * threatTypes.length)],
      severity: severities[Math.floor(Math.random() * severities.length)],
      source: `${location.country}-${Math.floor(Math.random() * 1000)}`,
      sourceIP: generateRandomIP(),
      targetIP: generateInternalIP(),
      country: location.country,
      city: location.city,
      latitude: location.lat + (Math.random() - 0.5) * 2,
      longitude: location.lng + (Math.random() - 0.5) * 2,
      description: descriptions[Math.floor(Math.random() * descriptions.length)],
      details: {
        attackVector: attackVectors[Math.floor(Math.random() * attackVectors.length)],
        confidence: Math.floor(Math.random() * 40) + 60,
        affectedSystems: Math.floor(Math.random() * 5) + 1,
        mitreTactic: mitreTactics[Math.floor(Math.random() * mitreTactics.length)],
        threatIntel: Math.random() > 0.5 ? 'VirusTotal' : 'MISP Feed'
      },
      status: 'active',
      attackVector: attackVectors[Math.floor(Math.random() * attackVectors.length)],
      mitreTactic: mitreTactics[Math.floor(Math.random() * mitreTactics.length)],
      assetType: assetTypes[Math.floor(Math.random() * assetTypes.length)],
      confidence: Math.floor(Math.random() * 40) + 60
    };
  };

  const generateRandomIP = (): string => {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  };

  const generateInternalIP = (): string => {
    return `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  };

  const simulateRealTimeThreats = () => {
    if (Math.random() < 0.4) { // 40% chance of new threat
      const newThreat = generateMockThreat();
      setThreats(prev => [newThreat, ...prev.slice(0, 99)]);

      // Auto-alert for critical threats
      if (newThreat.severity === 'critical') {
        const alertData = createThreatAlert(
          'system@agentphantom.ai',
          newThreat.description,
          'dangerous',
          newThreat.id
        );
        addAlert(alertData);
      }
    }

    // Update metrics
    setMetrics(prev => ({
      networkTraffic: Math.max(0, prev.networkTraffic + (Math.random() - 0.5) * 20),
      endpointAlerts: Math.max(0, prev.endpointAlerts + Math.floor(Math.random() * 3)),
      malwareDetections: Math.max(0, prev.malwareDetections + Math.floor(Math.random() * 2)),
      anomalies: Math.max(0, prev.anomalies + Math.floor(Math.random() * 2)),
      threatIntelHits: Math.max(0, prev.threatIntelHits + Math.floor(Math.random() * 5))
    }));
  };

  const updateHeatmapData = () => {
    const countryThreatCounts = new Map<string, { count: number; maxSeverity: string }>();
    
    threats.forEach(threat => {
      const current = countryThreatCounts.get(threat.country) || { count: 0, maxSeverity: 'low' };
      current.count += 1;
      
      const severityOrder = { low: 1, medium: 2, high: 3, critical: 4 };
      if (severityOrder[threat.severity] > severityOrder[current.maxSeverity as keyof typeof severityOrder]) {
        current.maxSeverity = threat.severity;
      }
      
      countryThreatCounts.set(threat.country, current);
    });

    const heatmapData: HeatmapData[] = Array.from(countryThreatCounts.entries()).map(([country, data]) => {
      const location = mockLocations.find(loc => loc.country === country);
      return {
        country,
        threatCount: data.count,
        severity: data.maxSeverity as 'low' | 'medium' | 'high' | 'critical',
        coordinates: location ? [location.lat, location.lng] : [0, 0]
      };
    });

    setHeatmapData(heatmapData);
  };

  const updateAttackPaths = () => {
    const paths: AttackPath[] = [];
    const recentThreats = threats.slice(0, 10);
    
    recentThreats.forEach((threat, index) => {
      if (index < recentThreats.length - 1) {
        paths.push({
          id: `path_${threat.id}`,
          source: threat.sourceIP,
          target: threat.targetIP || generateInternalIP(),
          technique: threat.mitreTactic,
          severity: threat.severity,
          timestamp: threat.timestamp
        });
      }
    });

    setAttackPaths(paths);
  };

  const applyFilters = (threats: ThreatEvent[]) => {
    return threats.filter(threat => {
      const severityMatch = filters.severity === 'all' || threat.severity === filters.severity;
      const typeMatch = filters.type === 'all' || threat.type === filters.type;
      const countryMatch = filters.country === 'all' || threat.country === filters.country;
      const assetMatch = filters.assetType === 'all' || threat.assetType === filters.assetType;
      const statusMatch = filters.status === 'all' || threat.status === filters.status;
      
      // Time range filter
      const now = new Date();
      const timeRangeMs = {
        '1h': 3600000,
        '24h': 86400000,
        '7d': 604800000,
        '30d': 2592000000
      };
      const cutoff = new Date(now.getTime() - timeRangeMs[filters.timeRange as keyof typeof timeRangeMs]);
      const timeMatch = threat.timestamp >= cutoff;
      
      return severityMatch && typeMatch && countryMatch && assetMatch && statusMatch && timeMatch;
    });
  };

  const filteredThreats = applyFilters(threats);
  const criticalThreats = filteredThreats.filter(t => t.severity === 'critical').length;
  const activeThreats = filteredThreats.filter(t => t.status === 'active').length;

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/20 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/20 border-orange-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
      case 'low': return 'text-blue-400 bg-blue-500/20 border-blue-500/30';
      default: return 'text-gray-400 bg-gray-500/20 border-gray-500/30';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'network': return <Network className="w-5 h-5" />;
      case 'endpoint': return <Server className="w-5 h-5" />;
      case 'malware': return <Shield className="w-5 h-5" />;
      case 'anomaly': return <TrendingUp className="w-5 h-5" />;
      case 'intelligence': return <Database className="w-5 h-5" />;
      default: return <AlertTriangle className="w-5 h-5" />;
    }
  };

  const getHeatmapColor = (severity: string, opacity: number = 0.7) => {
    const colors = {
      critical: `rgba(239, 68, 68, ${opacity})`,
      high: `rgba(249, 115, 22, ${opacity})`,
      medium: `rgba(234, 179, 8, ${opacity})`,
      low: `rgba(59, 130, 246, ${opacity})`
    };
    return colors[severity as keyof typeof colors] || colors.low;
  };

  const exportThreatData = () => {
    const data = {
      threats: filteredThreats,
      heatmapData,
      attackPaths,
      metrics,
      exportTime: new Date().toISOString()
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-intelligence-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-black via-gray-900 to-black">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_80%,rgba(239,68,68,0.1),transparent)] pointer-events-none" />
      
      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-4xl font-bold bg-gradient-to-r from-red-400 to-orange-500 bg-clip-text text-transparent mb-2">
              🔴 Advanced Threat Intelligence
            </h1>
            <p className="text-gray-300">Real-time monitoring with geospatial analysis and attack visualization</p>
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
              onClick={exportThreatData}
              className="px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded-lg font-medium transition-colors flex items-center space-x-2"
            >
              <Download className="w-4 h-4" />
              <span>Export</span>
            </button>
            
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

        {/* View Selector */}
        <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-2 mb-8">
          <div className="flex space-x-2">
            {[
              { id: 'overview', label: '📊 Overview', icon: BarChart3 },
              { id: 'heatmap', label: '🗺️ Threat Heatmap', icon: MapIcon },
              { id: 'attack-graph', label: '🕸️ Attack Graph', icon: Network },
              { id: 'geolocation', label: '🌍 Geolocation', icon: Globe }
            ].map((view) => {
              const Icon = view.icon;
              return (
                <button
                  key={view.id}
                  onClick={() => setActiveView(view.id as any)}
                  className={`flex-1 px-6 py-3 rounded-xl font-medium transition-all duration-200 flex items-center justify-center space-x-2 ${
                    activeView === view.id
                      ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                      : 'text-gray-400 hover:text-white hover:bg-gray-700/30'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span className="hidden sm:inline">{view.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Filters */}
        <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-6 mb-8">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-bold text-white flex items-center">
              <Filter className="w-5 h-5 mr-2 text-blue-400" />
              Advanced Filters
            </h3>
            <button
              onClick={() => setFilters({
                severity: 'all',
                type: 'all',
                country: 'all',
                assetType: 'all',
                timeRange: '24h',
                status: 'all'
              })}
              className="px-3 py-1 bg-gray-600/20 hover:bg-gray-600/30 text-gray-400 rounded text-sm transition-colors"
            >
              Clear All
            </button>
          </div>
          
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            <select
              value={filters.severity}
              onChange={(e) => setFilters(prev => ({ ...prev, severity: e.target.value }))}
              className="px-3 py-2 bg-black/50 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-red-500/50"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <select
              value={filters.type}
              onChange={(e) => setFilters(prev => ({ ...prev, type: e.target.value }))}
              className="px-3 py-2 bg-black/50 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-red-500/50"
            >
              <option value="all">All Types</option>
              <option value="network">Network</option>
              <option value="endpoint">Endpoint</option>
              <option value="malware">Malware</option>
              <option value="anomaly">Anomaly</option>
              <option value="intelligence">Intelligence</option>
            </select>

            <select
              value={filters.country}
              onChange={(e) => setFilters(prev => ({ ...prev, country: e.target.value }))}
              className="px-3 py-2 bg-black/50 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-red-500/50"
            >
              <option value="all">All Countries</option>
              {Array.from(new Set(threats.map(t => t.country))).map(country => (
                <option key={country} value={country}>{country}</option>
              ))}
            </select>

            <select
              value={filters.assetType}
              onChange={(e) => setFilters(prev => ({ ...prev, assetType: e.target.value }))}
              className="px-3 py-2 bg-black/50 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-red-500/50"
            >
              <option value="all">All Assets</option>
              <option value="Server">Server</option>
              <option value="Workstation">Workstation</option>
              <option value="Network Device">Network Device</option>
              <option value="Database">Database</option>
              <option value="Web Application">Web Application</option>
              <option value="Mobile Device">Mobile Device</option>
            </select>

            <select
              value={filters.timeRange}
              onChange={(e) => setFilters(prev => ({ ...prev, timeRange: e.target.value }))}
              className="px-3 py-2 bg-black/50 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-red-500/50"
            >
              <option value="1h">Last Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>

            <select
              value={filters.status}
              onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
              className="px-3 py-2 bg-black/50 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-red-500/50"
            >
              <option value="all">All Statuses</option>
              <option value="active">Active</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>
        </div>

        {/* Metrics Dashboard */}
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
          <div className="bg-red-500/10 border border-red-500/20 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <AlertTriangle className="w-8 h-8 text-red-400" />
              <div className="text-right">
                <div className="text-2xl font-bold text-white">{criticalThreats}</div>
                <div className="text-sm text-red-400">Critical</div>
              </div>
            </div>
            <div className="text-xs text-gray-400">Active critical threats</div>
          </div>

          <div className="bg-orange-500/10 border border-orange-500/20 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <Activity className="w-8 h-8 text-orange-400" />
              <div className="text-right">
                <div className="text-2xl font-bold text-white">{activeThreats}</div>
                <div className="text-sm text-orange-400">Active</div>
              </div>
            </div>
            <div className="text-xs text-gray-400">Total active threats</div>
          </div>

          <div className="bg-blue-500/10 border border-blue-500/20 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <Globe className="w-8 h-8 text-blue-400" />
              <div className="text-right">
                <div className="text-2xl font-bold text-white">{heatmapData.length}</div>
                <div className="text-sm text-blue-400">Countries</div>
              </div>
            </div>
            <div className="text-xs text-gray-400">Threat origins</div>
          </div>

          <div className="bg-purple-500/10 border border-purple-500/20 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <Network className="w-8 h-8 text-purple-400" />
              <div className="text-right">
                <div className="text-2xl font-bold text-white">{attackPaths.length}</div>
                <div className="text-sm text-purple-400">Attack Paths</div>
              </div>
            </div>
            <div className="text-xs text-gray-400">Active attack chains</div>
          </div>

          <div className="bg-green-500/10 border border-green-500/20 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <Database className="w-8 h-8 text-green-400" />
              <div className="text-right">
                <div className="text-2xl font-bold text-white">{metrics.threatIntelHits}</div>
                <div className="text-sm text-green-400">Intel Hits</div>
              </div>
            </div>
            <div className="text-xs text-gray-400">Threat intelligence</div>
          </div>
        </div>

        {/* Main Content Area */}
        {activeView === 'overview' && (
          <div className="space-y-8">
            {/* Live Threat Feed */}
            <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold text-white flex items-center">
                  <Eye className="w-6 h-6 mr-3 text-red-400" />
                  Live Threat Feed ({filteredThreats.length})
                </h2>
              </div>

              <div className="space-y-4 max-h-96 overflow-y-auto">
                {filteredThreats.length === 0 ? (
                  <div className="text-center py-8">
                    <Shield className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                    <p className="text-gray-400">No threats detected matching current filters</p>
                  </div>
                ) : (
                  filteredThreats.slice(0, 20).map((threat) => (
                    <div
                      key={threat.id}
                      onClick={() => setSelectedThreat(threat)}
                      className={`border rounded-xl p-4 cursor-pointer transition-all duration-200 hover:scale-[1.02] ${
                        getSeverityColor(threat.severity)
                      } ${
                        threat.status === 'active' ? 'ring-2 ring-red-500/30' : ''
                      }`}
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center space-x-3">
                          {getTypeIcon(threat.type)}
                          <div>
                            <div className="font-bold text-sm capitalize flex items-center space-x-2">
                              <span>{threat.type} Threat • {threat.severity.toUpperCase()}</span>
                              <span className="text-xs bg-gray-700/50 px-2 py-1 rounded">
                                🌍 {threat.country}
                              </span>
                            </div>
                            <div className="text-xs opacity-75">
                              {threat.sourceIP} → {threat.targetIP} • {threat.timestamp.toLocaleTimeString()}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className={`px-2 py-1 rounded text-xs font-medium ${
                            threat.status === 'active' ? 'bg-red-500/20 text-red-400' :
                            threat.status === 'investigating' ? 'bg-yellow-500/20 text-yellow-400' :
                            'bg-green-500/20 text-green-400'
                          }`}>
                            {threat.status.toUpperCase()}
                          </span>
                        </div>
                      </div>

                      <p className="text-sm mb-3 leading-relaxed">{threat.description}</p>

                      <div className="flex items-center justify-between text-xs">
                        <div className="flex space-x-4">
                          <span>Vector: {threat.attackVector}</span>
                          <span>Confidence: {threat.confidence}%</span>
                          <span>Asset: {threat.assetType}</span>
                        </div>
                        <div className="text-right">
                          <span>MITRE: {threat.mitreTactic}</span>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {activeView === 'heatmap' && (
          <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-white flex items-center">
                <MapIcon className="w-6 h-6 mr-3 text-blue-400" />
                Global Threat Heatmap
              </h2>
              <button className="px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded-lg transition-colors flex items-center space-x-2">
                <Maximize2 className="w-4 h-4" />
                <span>Fullscreen</span>
              </button>
            </div>

            {/* Heatmap Visualization */}
            <div className="bg-black/30 rounded-xl p-6 mb-6" style={{ height: '400px' }}>
              <div className="relative w-full h-full bg-gray-800/30 rounded-lg overflow-hidden">
                {/* World Map Placeholder */}
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="text-center">
                    <Globe className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                    <p className="text-gray-400 text-lg font-medium">Interactive World Map</p>
                    <p className="text-gray-500 text-sm">Threat density visualization by country</p>
                  </div>
                </div>

                {/* Threat Markers */}
                {heatmapData.map((data, index) => (
                  <div
                    key={data.country}
                    className="absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer"
                    style={{
                      left: `${50 + (index % 5 - 2) * 15}%`,
                      top: `${50 + (Math.floor(index / 5) - 1) * 20}%`
                    }}
                    title={`${data.country}: ${data.threatCount} threats`}
                  >
                    <div
                      className="rounded-full border-2 border-white/50 animate-pulse"
                      style={{
                        backgroundColor: getHeatmapColor(data.severity),
                        width: `${Math.max(20, data.threatCount * 3)}px`,
                        height: `${Math.max(20, data.threatCount * 3)}px`
                      }}
                    />
                    <div className="absolute -bottom-6 left-1/2 transform -translate-x-1/2 text-xs text-white font-medium whitespace-nowrap">
                      {data.country}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Heatmap Legend */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {['critical', 'high', 'medium', 'low'].map(severity => (
                <div key={severity} className="flex items-center space-x-3">
                  <div
                    className="w-4 h-4 rounded-full border border-white/30"
                    style={{ backgroundColor: getHeatmapColor(severity) }}
                  />
                  <span className="text-gray-300 capitalize">{severity} Threats</span>
                </div>
              ))}
            </div>

            {/* Country Statistics */}
            <div className="mt-8">
              <h3 className="text-lg font-bold text-white mb-4">Top Threat Origins</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {heatmapData
                  .sort((a, b) => b.threatCount - a.threatCount)
                  .slice(0, 6)
                  .map((data) => (
                    <div key={data.country} className="bg-black/30 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-white font-medium">{data.country}</span>
                        <span className={`px-2 py-1 rounded text-xs ${getSeverityColor(data.severity)}`}>
                          {data.severity.toUpperCase()}
                        </span>
                      </div>
                      <div className="text-2xl font-bold text-white">{data.threatCount}</div>
                      <div className="text-sm text-gray-400">Active threats</div>
                    </div>
                  ))}
              </div>
            </div>
          </div>
        )}

        {activeView === 'attack-graph' && (
          <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-white flex items-center">
                <Network className="w-6 h-6 mr-3 text-purple-400" />
                Attack Chain Visualization
              </h2>
              <div className="flex space-x-2">
                <button className="px-3 py-1 bg-purple-500/20 hover:bg-purple-500/30 text-purple-400 rounded text-sm transition-colors">
                  Auto-Layout
                </button>
                <button className="px-3 py-1 bg-gray-600/20 hover:bg-gray-600/30 text-gray-400 rounded text-sm transition-colors">
                  Reset View
                </button>
              </div>
            </div>

            {/* Attack Graph Visualization */}
            <div className="bg-black/30 rounded-xl p-6 mb-6" style={{ height: '500px' }}>
              <div className="relative w-full h-full">
                {/* Network Topology */}
                <svg className="w-full h-full">
                  {/* Background Grid */}
                  <defs>
                    <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
                      <path d="M 20 0 L 0 0 0 20" fill="none" stroke="rgba(75, 85, 99, 0.2)" strokeWidth="1"/>
                    </pattern>
                  </defs>
                  <rect width="100%" height="100%" fill="url(#grid)" />

                  {/* Attack Paths */}
                  {attackPaths.map((path, index) => {
                    const startX = 100 + (index % 3) * 200;
                    const startY = 100 + Math.floor(index / 3) * 150;
                    const endX = startX + 150;
                    const endY = startY + (Math.random() - 0.5) * 100;
                    
                    return (
                      <g key={path.id}>
                        {/* Attack Path Line */}
                        <line
                          x1={startX}
                          y1={startY}
                          x2={endX}
                          y2={endY}
                          stroke={path.severity === 'critical' ? '#ef4444' : 
                                 path.severity === 'high' ? '#f97316' : 
                                 path.severity === 'medium' ? '#eab308' : '#3b82f6'}
                          strokeWidth="3"
                          strokeDasharray={path.severity === 'critical' ? '0' : '5,5'}
                          opacity="0.8"
                        />
                        
                        {/* Arrow Head */}
                        <polygon
                          points={`${endX-10},${endY-5} ${endX},${endY} ${endX-10},${endY+5}`}
                          fill={path.severity === 'critical' ? '#ef4444' : 
                               path.severity === 'high' ? '#f97316' : 
                               path.severity === 'medium' ? '#eab308' : '#3b82f6'}
                        />
                        
                        {/* Source Node */}
                        <circle
                          cx={startX}
                          cy={startY}
                          r="15"
                          fill="rgba(239, 68, 68, 0.2)"
                          stroke="#ef4444"
                          strokeWidth="2"
                        />
                        <text x={startX} y={startY-25} textAnchor="middle" fill="#ef4444" fontSize="12">
                          {path.source.split('.').slice(-1)[0]}
                        </text>
                        
                        {/* Target Node */}
                        <circle
                          cx={endX}
                          cy={endY}
                          r="15"
                          fill="rgba(34, 197, 94, 0.2)"
                          stroke="#22c55e"
                          strokeWidth="2"
                        />
                        <text x={endX} y={endY-25} textAnchor="middle" fill="#22c55e" fontSize="12">
                          {path.target.split('.').slice(-1)[0]}
                        </text>
                        
                        {/* Technique Label */}
                        <text
                          x={(startX + endX) / 2}
                          y={(startY + endY) / 2 - 10}
                          textAnchor="middle"
                          fill="#9ca3af"
                          fontSize="10"
                        >
                          {path.technique}
                        </text>
                      </g>
                    );
                  })}
                </svg>
              </div>
            </div>

            {/* Attack Techniques Legend */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <div className="bg-black/30 rounded-lg p-4">
                <h4 className="text-white font-medium mb-3">MITRE ATT&CK Techniques</h4>
                <div className="space-y-2">
                  {Array.from(new Set(attackPaths.map(p => p.technique))).slice(0, 5).map(technique => (
                    <div key={technique} className="flex items-center space-x-2">
                      <div className="w-2 h-2 bg-purple-400 rounded-full" />
                      <span className="text-gray-300 text-sm">{technique}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-black/30 rounded-lg p-4">
                <h4 className="text-white font-medium mb-3">Attack Severity</h4>
                <div className="space-y-2">
                  {['critical', 'high', 'medium', 'low'].map(severity => (
                    <div key={severity} className="flex items-center space-x-2">
                      <div className={`w-3 h-3 rounded-full ${
                        severity === 'critical' ? 'bg-red-400' :
                        severity === 'high' ? 'bg-orange-400' :
                        severity === 'medium' ? 'bg-yellow-400' : 'bg-blue-400'
                      }`} />
                      <span className="text-gray-300 text-sm capitalize">{severity}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-black/30 rounded-lg p-4">
                <h4 className="text-white font-medium mb-3">Network Nodes</h4>
                <div className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <div className="w-3 h-3 bg-red-400 rounded-full" />
                    <span className="text-gray-300 text-sm">External Sources</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="w-3 h-3 bg-green-400 rounded-full" />
                    <span className="text-gray-300 text-sm">Internal Targets</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeView === 'geolocation' && (
          <div className="bg-gray-900/50 backdrop-blur-xl border border-gray-700/50 rounded-2xl p-8">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-white flex items-center">
                <Globe className="w-6 h-6 mr-3 text-green-400" />
                Geospatial Threat Analysis
              </h2>
              <div className="flex space-x-2">
                <button className="px-3 py-1 bg-green-500/20 hover:bg-green-500/30 text-green-400 rounded text-sm transition-colors">
                  Satellite View
                </button>
                <button className="px-3 py-1 bg-gray-600/20 hover:bg-gray-600/30 text-gray-400 rounded text-sm transition-colors">
                  Street View
                </button>
              </div>
            </div>

            {/* Geolocation Map */}
            <div className="bg-black/30 rounded-xl p-6 mb-6" style={{ height: '400px' }}>
              <div className="relative w-full h-full bg-gradient-to-br from-blue-900/20 to-green-900/20 rounded-lg overflow-hidden">
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="text-center">
                    <Globe className="w-16 h-16 text-green-400 mx-auto mb-4 animate-spin" />
                    <p className="text-green-400 text-lg font-medium">Real-time Geospatial Tracking</p>
                    <p className="text-gray-400 text-sm">Threat origins and attack vectors</p>
                  </div>
                </div>

                {/* Threat Origin Points */}
                {filteredThreats.slice(0, 15).map((threat, index) => (
                  <div
                    key={threat.id}
                    className="absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer group"
                    style={{
                      left: `${20 + (index % 8) * 10}%`,
                      top: `${20 + Math.floor(index / 8) * 15}%`
                    }}
                  >
                    <div className={`w-3 h-3 rounded-full animate-pulse ${
                      threat.severity === 'critical' ? 'bg-red-400' :
                      threat.severity === 'high' ? 'bg-orange-400' :
                      threat.severity === 'medium' ? 'bg-yellow-400' : 'bg-blue-400'
                    }`} />
                    
                    {/* Tooltip */}
                    <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 opacity-0 group-hover:opacity-100 transition-opacity bg-black/90 text-white text-xs rounded px-2 py-1 whitespace-nowrap z-10">
                      {threat.city}, {threat.country}
                      <br />
                      {threat.severity.toUpperCase()} - {threat.type}
                    </div>
                  </div>
                ))}

                {/* Attack Vectors */}
                <svg className="absolute inset-0 w-full h-full pointer-events-none">
                  {filteredThreats.slice(0, 10).map((threat, index) => {
                    const startX = 20 + (index % 8) * 10;
                    const startY = 20 + Math.floor(index / 8) * 15;
                    const endX = 80;
                    const endY = 50;
                    
                    return (
                      <line
                        key={threat.id}
                        x1={`${startX}%`}
                        y1={`${startY}%`}
                        x2={`${endX}%`}
                        y2={`${endY}%`}
                        stroke={threat.severity === 'critical' ? '#ef4444' : '#f97316'}
                        strokeWidth="1"
                        strokeDasharray="3,3"
                        opacity="0.6"
                        className="animate-pulse"
                      />
                    );
                  })}
                </svg>
              </div>
            </div>

            {/* Geographic Statistics */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-black/30 rounded-lg p-6">
                <h4 className="text-white font-medium mb-4">Top Attack Origins</h4>
                <div className="space-y-3">
                  {Object.entries(
                    filteredThreats.reduce((acc, threat) => {
                      acc[threat.country] = (acc[threat.country] || 0) + 1;
                      return acc;
                    }, {} as Record<string, number>)
                  )
                    .sort(([,a], [,b]) => b - a)
                    .slice(0, 5)
                    .map(([country, count]) => (
                      <div key={country} className="flex items-center justify-between">
                        <span className="text-gray-300">{country}</span>
                        <span className="text-white font-bold">{count}</span>
                      </div>
                    ))}
                </div>
              </div>

              <div className="bg-black/30 rounded-lg p-6">
                <h4 className="text-white font-medium mb-4">Attack Vectors</h4>
                <div className="space-y-3">
                  {Object.entries(
                    filteredThreats.reduce((acc, threat) => {
                      acc[threat.attackVector] = (acc[threat.attackVector] || 0) + 1;
                      return acc;
                    }, {} as Record<string, number>)
                  )
                    .sort(([,a], [,b]) => b - a)
                    .slice(0, 5)
                    .map(([vector, count]) => (
                      <div key={vector} className="flex items-center justify-between">
                        <span className="text-gray-300">{vector}</span>
                        <span className="text-white font-bold">{count}</span>
                      </div>
                    ))}
                </div>
              </div>

              <div className="bg-black/30 rounded-lg p-6">
                <h4 className="text-white font-medium mb-4">Threat Timeline</h4>
                <div className="space-y-3">
                  {filteredThreats
                    .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
                    .slice(0, 5)
                    .map((threat) => (
                      <div key={threat.id} className="text-sm">
                        <div className="text-gray-300">{threat.timestamp.toLocaleTimeString()}</div>
                        <div className="text-white">{threat.country} - {threat.type}</div>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Threat Detail Modal */}
        {selectedThreat && (
          <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-gray-900 border border-gray-700 rounded-2xl p-8 max-w-4xl w-full max-h-[90vh] overflow-y-auto">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-2xl font-bold text-white">Threat Analysis: {selectedThreat.id}</h3>
                <button
                  onClick={() => setSelectedThreat(null)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  ✕
                </button>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Left Column */}
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-bold text-white mb-4">Threat Information</h4>
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Type:</span>
                        <span className="text-white capitalize">{selectedThreat.type}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Severity:</span>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(selectedThreat.severity)}`}>
                          {selectedThreat.severity.toUpperCase()}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Status:</span>
                        <span className="text-white capitalize">{selectedThreat.status}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Confidence:</span>
                        <span className="text-white">{selectedThreat.confidence}%</span>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-bold text-white mb-4">Network Information</h4>
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Source IP:</span>
                        <span className="text-white font-mono">{selectedThreat.sourceIP}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Target IP:</span>
                        <span className="text-white font-mono">{selectedThreat.targetIP}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Origin:</span>
                        <span className="text-white">{selectedThreat.city}, {selectedThreat.country}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Attack Vector:</span>
                        <span className="text-white">{selectedThreat.attackVector}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Right Column */}
                <div className="space-y-6">
                  <div>
                    <h4 className="text-lg font-bold text-white mb-4">MITRE ATT&CK</h4>
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Tactic:</span>
                        <span className="text-white">{selectedThreat.mitreTactic}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Asset Type:</span>
                        <span className="text-white">{selectedThreat.assetType}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Detection Time:</span>
                        <span className="text-white">{selectedThreat.timestamp.toLocaleString()}</span>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-lg font-bold text-white mb-4">Description</h4>
                    <p className="text-gray-300 leading-relaxed">{selectedThreat.description}</p>
                  </div>

                  <div>
                    <h4 className="text-lg font-bold text-white mb-4">Additional Details</h4>
                    <div className="bg-black/30 rounded-lg p-4">
                      <pre className="text-gray-300 text-sm">
                        {JSON.stringify(selectedThreat.details, null, 2)}
                      </pre>
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

export default ThreatMonitor;