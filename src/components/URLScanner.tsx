import React, { useState, useEffect } from 'react';
import { Link, Search, Shield, AlertTriangle, Ban, Copy, Zap, Terminal } from 'lucide-react';
import { analyzeURL } from '../utils/mockAI';
import { ScanResult } from '../types';
import { useAlert } from '../contexts/AlertContext';
import { createThreatAlert } from '../utils/alertUtils';

interface URLScannerProps {
  onNavigate: (page: string) => void;
}

const URLScanner: React.FC<URLScannerProps> = ({ onNavigate }) => {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState('');
  const [scanProgress, setScanProgress] = useState(0);
  const [scanPhase, setScanPhase] = useState('');
  const { addAlert } = useAlert();

  // Simulate scanning progress
  useEffect(() => {
    if (isScanning) {
      const phases = [
        'INITIALIZING SCAN...',
        'CHECKING URL STRUCTURE...',
        'ANALYZING DOMAIN REPUTATION...',
        'INSPECTING SSL CERTIFICATES...',
        'CHECKING THREAT INTELLIGENCE...',
        'SCANNING FOR MALICIOUS PATTERNS...',
        'VERIFYING REDIRECT CHAINS...',
        'EVALUATING CONTENT SAFETY...',
        'FINALIZING SECURITY REPORT...'
      ];
      
      let currentPhase = 0;
      let progress = 0;
      
      const interval = setInterval(() => {
        progress += Math.random() * 5 + 2;
        if (progress >= 100) {
          progress = 100;
          clearInterval(interval);
        }
        
        setScanProgress(progress);
        
        // Update phase text
        if (progress > (currentPhase + 1) * (100 / phases.length) && currentPhase < phases.length - 1) {
          currentPhase++;
          setScanPhase(phases[currentPhase]);
        } else if (currentPhase === 0) {
          setScanPhase(phases[0]);
        }
      }, 200);
      
      return () => clearInterval(interval);
    }
  }, [isScanning]);

  const validateURL = (urlString: string): boolean => {
    try {
      new URL(urlString);
      return true;
    } catch {
      return false;
    }
  };

  const handleScan = async () => {
    setError('');
    
    if (!url.trim()) {
      setError('Please enter a URL to scan');
      return;
    }

    if (!validateURL(url)) {
      setError('Please enter a valid URL (include http:// or https://)');
      return;
    }

    setIsScanning(true);
    setResult(null);
    setScanProgress(0);
    setScanPhase('INITIALIZING SCAN...');

    try {
      const scanResult = await analyzeURL(url);
      setResult(scanResult);

      // 🚨 AUTO ALERT SYSTEM: Trigger alert for high-risk scans
      if (scanResult.riskLevel === 'dangerous') {
        const alertData = createThreatAlert(
          scanResult.userEmail || 'current.user@example.com',
          scanResult.target,
          scanResult.riskLevel,
          scanResult.id
        );
        addAlert(alertData);
      }
    } catch (err) {
      setError('Scan failed. Please try again.');
    } finally {
      setIsScanning(false);
    }
  };

  const copyReport = () => {
    if (result) {
      navigator.clipboard.writeText(result.report);
    }
  };

  const getRiskDisplay = () => {
    if (!result) return null;

    const riskConfig = {
      safe: {
        icon: Shield,
        color: 'text-cyber-primary',
        bg: 'bg-cyber-primary/20',
        border: 'border-cyber-primary/30',
        label: '✅ SAFE',
        description: 'This URL appears to be safe for browsing'
      },
      suspicious: {
        icon: AlertTriangle,
        color: 'text-cyber-warning',
        bg: 'bg-cyber-warning/20',
        border: 'border-cyber-warning/30',
        label: '⚠️ SUSPICIOUS',
        description: 'Exercise caution when visiting this URL'
      },
      dangerous: {
        icon: Ban,
        color: 'text-cyber-danger',
        bg: 'bg-cyber-danger/20',
        border: 'border-cyber-danger/30',
        label: '🚫 DANGEROUS',
        description: 'This URL poses significant security risks'
      }
    };

    return riskConfig[result.riskLevel];
  };

  const riskDisplay = getRiskDisplay();

  return (
    <div className="min-h-screen bg-cyber-darker relative">
      {/* Cyberpunk background effects */}
      <div className="absolute inset-0 cyber-grid"></div>
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_30%,rgba(0,255,65,0.1),transparent)]"></div>
      <div className="hex-grid"></div>
      <div className="data-stream"></div>
      
      <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex justify-center mb-4">
            <div className="relative">
              <Link className="w-16 h-16 text-cyber-primary" />
              <div className="absolute inset-0 animate-cyber-pulse">
                <Link className="w-16 h-16 text-cyber-primary/30" />
              </div>
              <div className="absolute -inset-4 bg-cyber-primary/10 rounded-full blur-xl"></div>
            </div>
          </div>
          <h1 className="text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyber-primary to-cyber-accent mb-4 font-cyber">
            URL SECURITY SCANNER
          </h1>
          <p className="text-gray-300 text-lg max-w-2xl mx-auto font-cyber-alt">
            Enter a suspicious URL below to analyze it for phishing attempts, malware distribution, and other security threats.
          </p>
        </div>

        {/* Scanner Input */}
        <div className="cyber-card p-8 mb-8 border-cyber-primary/30">
          <div className="space-y-6">
            <div>
              <label htmlFor="url" className="block text-sm font-medium text-gray-300 mb-3 font-cyber">
                URL TO SCAN
              </label>
              <div className="flex space-x-4">
                <div className="flex-1 relative">
                  <input
                    type="url"
                    id="url"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://example.com"
                    className="w-full px-4 py-4 pl-12 bg-black/50 border border-cyber-primary/30 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyber-primary/50 focus:border-cyber-primary transition-all duration-200"
                    disabled={isScanning}
                  />
                  <Link className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-cyber-primary" />
                </div>
                <button
                  onClick={handleScan}
                  disabled={isScanning || !url.trim()}
                  className="cyber-button px-8 py-4 rounded-xl font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center space-x-2"
                >
                  {isScanning ? (
                    <>
                      <div className="cyber-loading" />
                      <span className="font-cyber">SCANNING...</span>
                    </>
                  ) : (
                    <>
                      <Search className="w-5 h-5" />
                      <span className="font-cyber">SCAN NOW</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {error && (
              <div className="bg-cyber-danger/10 border border-cyber-danger/20 rounded-lg p-4 text-cyber-danger">
                {error}
              </div>
            )}

            {/* Scanning Progress */}
            {isScanning && (
              <div className="space-y-3">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-cyber-primary font-cyber">{scanPhase}</span>
                  <span className="text-cyber-primary font-cyber">{Math.round(scanProgress)}%</span>
                </div>
                <div className="w-full h-2 bg-black/50 rounded-full overflow-hidden border border-cyber-primary/30">
                  <div 
                    className="h-full bg-gradient-to-r from-cyber-primary to-cyber-accent"
                    style={{ width: `${scanProgress}%` }}
                  ></div>
                </div>
                <div className="bg-black/30 border border-cyber-primary/20 rounded-lg p-3 font-mono text-xs text-cyber-primary overflow-hidden">
                  <Terminal className="w-4 h-4 inline-block mr-2" />
                  <span className="animate-pulse">Analyzing security parameters...</span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Scan Results */}
        {result && riskDisplay && (
          <div className="space-y-6">
            {/* Risk Level Badge */}
            <div className={`cyber-card ${riskDisplay.bg} ${riskDisplay.border} p-6`}>
              <div className="flex items-center space-x-4">
                <riskDisplay.icon className={`w-12 h-12 ${riskDisplay.color}`} />
                <div>
                  <h3 className={`text-2xl font-bold ${riskDisplay.color} font-cyber`}>
                    {riskDisplay.label}
                  </h3>
                  <p className="text-gray-300 mt-1 font-cyber-alt">{riskDisplay.description}</p>
                  {result.riskLevel === 'dangerous' && (
                    <div className="mt-3 bg-cyber-danger/10 border border-cyber-danger/20 rounded-lg p-3">
                      <p className="text-cyber-danger text-sm font-medium font-cyber">
                        🚨 CRITICAL ALERT: Officers have been automatically notified
                      </p>
                      <p className="text-red-300 text-xs mt-1">
                        📧 Email alert sent to vanursab71@gmail.com and security team
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Detailed Report */}
            <div className="cyber-card p-8 border-cyber-primary/30">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-bold text-white font-cyber">SECURITY REPORT</h3>
                <div className="flex space-x-3">
                  <button
                    onClick={copyReport}
                    className="px-4 py-2 bg-gray-700/50 hover:bg-gray-600/50 text-gray-300 rounded-lg transition-colors flex items-center space-x-2"
                  >
                    <Copy className="w-4 h-4" />
                    <span className="font-cyber">COPY</span>
                  </button>
                </div>
              </div>

              <div className="bg-black/30 rounded-xl p-6 border border-gray-700/30">
                <div className="text-gray-300 whitespace-pre-line leading-relaxed font-cyber-alt">
                  {result.report}
                </div>
              </div>

              <div className="mt-6 flex items-center justify-between text-sm text-gray-400">
                <span className="font-mono">TARGET: {result.target}</span>
                <span className="font-mono">TIMESTAMP: {result.timestamp.toLocaleTimeString()}</span>
              </div>
            </div>
          </div>
        )}

        {/* Quick Actions */}
        <div className="mt-12 grid md:grid-cols-2 gap-6">
          <button
            onClick={() => onNavigate('file-upload')}
            className="cyber-card group p-6 text-left transition-all duration-300 hover:scale-105 border-cyber-accent/30"
          >
            <h3 className="text-lg font-bold text-white mb-2 font-cyber">ANALYZE A FILE NEXT</h3>
            <p className="text-gray-300 font-cyber-alt">Upload suspicious files for malware analysis</p>
          </button>
          
          <button
            onClick={() => onNavigate('dashboard')}
            className="cyber-card group p-6 text-left transition-all duration-300 hover:scale-105 border-gray-600/30"
          >
            <h3 className="text-lg font-bold text-white mb-2 font-cyber">BACK TO DASHBOARD</h3>
            <p className="text-gray-300 font-cyber-alt">Return to your security command center</p>
          </button>
        </div>

        
      </div>
    </div>
  );
};

export default URLScanner;