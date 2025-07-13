import React, { useState, useEffect } from 'react';
import { Link, Upload, Shield, Zap, Eye, TrendingUp, Mail, Settings, QrCode, Activity, AlertTriangle, Target, Database, Search, Brain } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useAlert } from '../contexts/AlertContext';

interface DashboardProps {
  onNavigate: (page: string) => void;
}

const Dashboard: React.FC<DashboardProps> = ({ onNavigate }) => {
  const { user } = useAuth();
  const { getUnreadCount, getCriticalCount } = useAlert();
  const [currentTime, setCurrentTime] = useState(new Date());
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Simulate loading
    const timer = setTimeout(() => {
      setIsLoading(false);
    }, 1500);

    // Update time every second
    const timeInterval = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);

    return () => {
      clearTimeout(timer);
      clearInterval(timeInterval);
    };
  }, []);

  const stats = [
    { label: 'URLs Scanned', value: '1,247', icon: Link, color: 'green' },
    { label: 'QR Codes Checked', value: '456', icon: QrCode, color: 'orange' },
    { label: 'Files Analyzed', value: '892', icon: Upload, color: 'purple' },
    { label: 'Threats Blocked', value: '43', icon: Shield, color: 'red' },
    { label: 'Vulnerabilities', value: '12', icon: Target, color: 'blue' },
    { label: 'DLP Violations', value: '8', icon: Database, color: 'cyan' },
    { label: 'Forensic Cases', value: '5', icon: Search, color: 'indigo' },
    { label: 'Incidents Handled', value: '8', icon: AlertTriangle, color: 'yellow' }
  ];

  const recentScans = [
    { type: 'URL', target: 'https://example-phishing.com', risk: 'dangerous', time: '2 min ago' },
    { type: 'QR Code', target: 'WiFi Network Credentials', risk: 'suspicious', time: '4 min ago' },
    { type: 'File', target: 'document.pdf', risk: 'safe', time: '5 min ago' },
    { type: 'DLP', target: 'PII Data Transfer Blocked', risk: 'dangerous', time: '6 min ago' },
    { type: 'Forensic', target: 'Evidence Analysis Complete', risk: 'safe', time: '7 min ago' },
    { type: 'Vulnerability', target: 'CVE-2024-1234 (Apache)', risk: 'dangerous', time: '8 min ago' },
    { type: 'Incident', target: 'APT Detection Alert', risk: 'dangerous', time: '12 min ago' },
    { type: 'URL', target: 'https://suspicious-site.net', risk: 'suspicious', time: '15 min ago' }
  ];

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'safe': return 'text-cyber-primary bg-cyber-primary/20';
      case 'suspicious': return 'text-cyber-warning bg-cyber-warning/20';
      case 'dangerous': return 'text-cyber-danger bg-cyber-danger/20';
      default: return 'text-gray-400 bg-gray-500/20';
    }
  };

  const getRiskIcon = (risk: string) => {
    switch (risk) {
      case 'safe': return '✅';
      case 'suspicious': return '⚠️';
      case 'dangerous': return '🚫';
      default: return '❓';
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-cyber-darker flex items-center justify-center">
        <div className="text-center">
          <div className="relative mb-6">
            <Shield className="w-16 h-16 text-cyber-primary mx-auto" />
            <div className="absolute inset-0 animate-cyber-pulse">
              <Shield className="w-16 h-16 text-cyber-primary/30 mx-auto" />
            </div>
          </div>
          <h2 className="text-2xl font-bold text-cyber-primary mb-4 font-cyber">INITIALIZING SECURITY DASHBOARD</h2>
          <div className="flex justify-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-cyber-primary animate-pulse" style={{ animationDelay: '0s' }}></div>
            <div className="w-3 h-3 rounded-full bg-cyber-primary animate-pulse" style={{ animationDelay: '0.2s' }}></div>
            <div className="w-3 h-3 rounded-full bg-cyber-primary animate-pulse" style={{ animationDelay: '0.4s' }}></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-cyber-darker relative">
      {/* Background effects */}
      <div className="absolute inset-0 cyber-grid"></div>
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_80%,rgba(0,255,65,0.1),transparent)] pointer-events-none"></div>
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_80%_20%,rgba(0,212,255,0.1),transparent)] pointer-events-none"></div>
      <div className="hex-grid"></div>
      <div className="data-stream"></div>
      
      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Welcome Section */}
        <div className="mb-12">
          <div className="cyber-card p-8 border-cyber-primary/30">
            <div className="flex flex-col md:flex-row items-center md:space-x-6">
              <div className="relative mb-6 md:mb-0">
                <Shield className="w-16 h-16 text-cyber-primary" />
                <div className="absolute inset-0 animate-cyber-pulse">
                  <Shield className="w-16 h-16 text-cyber-primary/30" />
                </div>
              </div>
              <div>
                <div className="flex items-center space-x-4 mb-2">
                  <h1 className="text-3xl font-bold text-white font-cyber">
                    WELCOME, <span className="text-cyber-primary">{user?.fullName.toUpperCase()}</span>
                  </h1>
                  <div className="px-3 py-1 bg-cyber-primary/20 text-cyber-primary rounded-lg text-xs font-cyber">
                    {currentTime.toLocaleTimeString()}
                  </div>
                </div>
                <p className="text-gray-300 text-lg font-cyber-alt">
                  Your comprehensive cybersecurity command center is ready. Scan URLs, QR codes, files, monitor threats, manage vulnerabilities, prevent data loss, and conduct digital forensics.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Email Alert Status */}
        <div className="mb-8">
          <div className="cyber-card p-6 border-cyber-accent/30 bg-gradient-to-r from-cyber-accent/5 to-transparent">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <Mail className="w-8 h-8 text-cyber-accent" />
                <div>
                  <h3 className="text-lg font-bold text-white font-cyber">EMAIL ALERT SYSTEM</h3>
                  <p className="text-gray-300">
                    Real-time notifications sent to <span className="text-cyber-accent font-medium">vanursab71@gmail.com</span>
                  </p>
                  <p className="text-gray-400 text-sm mt-1">
                    Officers are automatically notified of critical threats, DLP violations, forensic events, and security incidents
                  </p>
                </div>
              </div>
              <div className="flex items-center space-x-4">
                <div className="text-right">
                  <div className="text-sm text-gray-400 font-cyber">ACTIVE ALERTS</div>
                  <div className="text-xl font-bold text-cyber-warning font-cyber">{getUnreadCount()}</div>
                </div>
                <div className="text-right">
                  <div className="text-sm text-gray-400 font-cyber">CRITICAL</div>
                  <div className="text-xl font-bold text-cyber-danger font-cyber">{getCriticalCount()}</div>
                </div>
                <button
                  onClick={() => {/* Email setup is handled in Navigation */}}
                  className="p-2 bg-cyber-accent/20 hover:bg-cyber-accent/30 text-cyber-accent rounded-lg transition-colors"
                  title="Email setup handled in navigation"
                >
                  <Settings className="w-5 h-5" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
          <button
            onClick={() => onNavigate('url-scanner')}
            className="cyber-card group p-8 text-left transition-all duration-300 hover:scale-105 hover:shadow-cyber-md border-cyber-primary/30"
          >
            <div className="flex items-center space-x-4 mb-4">
              <div className="bg-cyber-primary/20 rounded-xl p-3 group-hover:bg-cyber-primary/30 transition-colors">
                <Link className="w-8 h-8 text-cyber-primary" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white font-cyber">URL SCANNER</h3>
                <p className="text-cyber-primary">Analyze suspicious links</p>
              </div>
            </div>
            <p className="text-gray-300">
              Detect phishing attempts, malware distribution, and other web-based threats.
            </p>
            <div className="mt-4 flex items-center text-cyber-primary font-medium">
              <span className="font-cyber">START URL ANALYSIS</span>
              <Zap className="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform" />
            </div>
          </button>

          <button
            onClick={() => onNavigate('qr-scanner')}
            className="cyber-card group p-8 text-left transition-all duration-300 hover:scale-105 hover:shadow-cyber-md border-cyber-warning/30"
          >
            <div className="flex items-center space-x-4 mb-4">
              <div className="bg-cyber-warning/20 rounded-xl p-3 group-hover:bg-cyber-warning/30 transition-colors">
                <QrCode className="w-8 h-8 text-cyber-warning" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white font-cyber">QR SCANNER</h3>
                <p className="text-cyber-warning">Check QR codes for threats</p>
              </div>
            </div>
            <p className="text-gray-300">
              Analyze QR code images for phishing URLs and malicious redirects.
            </p>
            <div className="mt-4 flex items-center text-cyber-warning font-medium">
              <span className="font-cyber">START QR ANALYSIS</span>
              <Zap className="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform" />
            </div>
          </button>

          <button
            onClick={() => onNavigate('data-loss-prevention')}
            className="cyber-card group p-8 text-left transition-all duration-300 hover:scale-105 hover:shadow-cyber-md border-cyber-accent/30"
          >
            <div className="flex items-center space-x-4 mb-4">
              <div className="bg-cyber-accent/20 rounded-xl p-3 group-hover:bg-cyber-accent/30 transition-colors">
                <Database className="w-8 h-8 text-cyber-accent" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white font-cyber">DATA LOSS</h3>
                <p className="text-cyber-accent">Monitor data transfers</p>
              </div>
            </div>
            <p className="text-gray-300">
              Detect and prevent unauthorized transfer of sensitive data.
            </p>
            <div className="mt-4 flex items-center text-cyber-accent font-medium">
              <span className="font-cyber">ACCESS DLP DASHBOARD</span>
              <Zap className="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform" />
            </div>
          </button>

          <button
            onClick={() => onNavigate('forensics-audit')}
            className="cyber-card group p-8 text-left transition-all duration-300 hover:scale-105 hover:shadow-cyber-md border-indigo-500/30"
          >
            <div className="flex items-center space-x-4 mb-4">
              <div className="bg-indigo-500/20 rounded-xl p-3 group-hover:bg-indigo-500/30 transition-colors">
                <Search className="w-8 h-8 text-indigo-400" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white font-cyber">FORENSICS</h3>
                <p className="text-indigo-400">Evidence & audit trails</p>
              </div>
            </div>
            <p className="text-gray-300">
              Comprehensive digital forensics and audit trail management.
            </p>
            <div className="mt-4 flex items-center text-indigo-400 font-medium">
              <span className="font-cyber">ACCESS FORENSICS</span>
              <Zap className="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform" />
            </div>
          </button>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 lg:grid-cols-8 gap-6 mb-12">
          {stats.map((stat, index) => {
            const Icon = stat.icon;
            const colorClasses = {
              green: 'from-cyber-primary/20 to-cyber-primary/10 border-cyber-primary/30 text-cyber-primary',
              orange: 'from-cyber-warning/20 to-cyber-warning/10 border-cyber-warning/30 text-cyber-warning',
              purple: 'from-purple-500/20 to-purple-600/20 border-purple-500/30 text-purple-400',
              red: 'from-cyber-danger/20 to-cyber-danger/10 border-cyber-danger/30 text-cyber-danger',
              blue: 'from-cyber-accent/20 to-cyber-accent/10 border-cyber-accent/30 text-cyber-accent',
              cyan: 'from-cyan-500/20 to-cyan-600/20 border-cyan-500/30 text-cyan-400',
              indigo: 'from-indigo-500/20 to-indigo-600/20 border-indigo-500/30 text-indigo-400',
              yellow: 'from-yellow-500/20 to-yellow-600/20 border-yellow-500/30 text-yellow-400'
            };
            
            return (
              <div
                key={index}
                className={`cyber-card bg-gradient-to-br ${colorClasses[stat.color as keyof typeof colorClasses]} border p-6 hover:scale-105 transition-all duration-300`}
              >
                <div className="flex items-center justify-between mb-4">
                  <Icon className="w-8 h-8" />
                  <Eye className="w-4 h-4 opacity-50" />
                </div>
                <div className="text-2xl font-bold text-white mb-1 font-cyber">{stat.value}</div>
                <div className="text-sm opacity-80 font-cyber-alt">{stat.label}</div>
              </div>
            );
          })}
        </div>

        {/* Recent Activity */}
        <div className="cyber-card p-8 border-cyber-primary/30">
          <h2 className="text-2xl font-bold text-white mb-6 flex items-center font-cyber">
            <Zap className="w-6 h-6 mr-3 text-cyber-primary" />
            SECURITY ACTIVITY
          </h2>
          
          <div className="space-y-4">
            {recentScans.map((scan, index) => (
              <div
                key={index}
                className="flex items-center justify-between p-4 bg-black/30 rounded-xl border border-gray-700/50 hover:border-cyber-primary/50 transition-colors"
              >
                <div className="flex items-center space-x-4">
                  <div className="w-10 h-10 bg-gray-800 rounded-lg flex items-center justify-center">
                    {scan.type === 'URL' ? (
                      <Link className="w-5 h-5 text-cyber-accent" />
                    ) : scan.type === 'QR Code' ? (
                      <QrCode className="w-5 h-5 text-cyber-warning" />
                    ) : scan.type === 'DLP' ? (
                      <Database className="w-5 h-5 text-cyan-400" />
                    ) : scan.type === 'Forensic' ? (
                      <Search className="w-5 h-5 text-indigo-400" />
                    ) : scan.type === 'Incident' ? (
                      <AlertTriangle className="w-5 h-5 text-cyber-danger" />
                    ) : scan.type === 'Vulnerability' ? (
                      <Target className="w-5 h-5 text-purple-400" />
                    ) : (
                      <Upload className="w-5 h-5 text-cyber-primary" />
                    )}
                  </div>
                  <div>
                    <div className="text-white font-medium font-cyber-alt">{scan.target}</div>
                    <div className="text-gray-400 text-sm">{scan.type} • {scan.time}</div>
                  </div>
                </div>
                <div className={`px-3 py-1 rounded-full text-xs font-medium ${getRiskColor(scan.risk)}`}>
                  {getRiskIcon(scan.risk)} {scan.risk.toUpperCase()}
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 text-center">
            <button 
              onClick={() => onNavigate('threat-monitor')}
              className="text-cyber-primary hover:text-cyber-primary/80 font-medium transition-colors font-cyber"
            >
              VIEW THREAT INTELLIGENCE →
            </button>
          </div>
        </div>

        

        {/* Contact Us Footer */}
        <div className="mt-8 text-center">
          <div className="inline-flex flex-col items-center px-6 py-4 bg-gradient-to-r from-cyber-primary/10 to-cyber-accent/10 border border-cyber-primary/20 rounded-xl">
            <span className="text-cyber-primary font-bold text-lg mb-2">Contact Us</span>
            <ContactForm />
          </div>
        </div>
      </div>
    </div>
  );
};

function ContactForm() {
  const [submitted, setSubmitted] = React.useState(false);

  return submitted ? (
    <div className="text-green-400 font-bold py-4">Submitted! Thank you for contacting us.</div>
  ) : (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        const form = e.target as HTMLFormElement;
        const data = new FormData(form);
        await fetch('https://formspree.io/f/xnnvlgvj', {
          method: 'POST',
          body: data,
          headers: { Accept: 'application/json' },
        });
        setSubmitted(true);
        form.reset();
      }}
      className="flex flex-col items-center space-y-2 w-full max-w-xs"
    >
      <input
        name="name"
        type="text"
        required
        placeholder="Your Name"
        className="w-full px-3 py-2 rounded bg-black/40 border border-cyber-primary/30 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-primary"
      />
      <input
        name="email"
        type="email"
        required
        placeholder="Your Email"
        className="w-full px-3 py-2 rounded bg-black/40 border border-cyber-primary/30 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-primary"
      />
      <textarea
        name="message"
        required
        placeholder="Your Message"
        rows={3}
        className="w-full px-3 py-2 rounded bg-black/40 border border-cyber-primary/30 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-primary resize-none"
      />
      <button
        type="submit"
        className="mt-2 px-4 py-2 bg-cyber-primary text-white rounded font-cyber hover:bg-cyber-accent transition-colors"
      >
        Send Message
      </button>
    </form>
  );
}

export default Dashboard;