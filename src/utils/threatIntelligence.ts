// Threat Intelligence and Detection Utilities
import { ScanResult } from '../types';

export interface ThreatIndicator {
  id: string;
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  value: string;
  confidence: number;
  source: string;
  firstSeen: Date;
  lastSeen: Date;
  tags: string[];
  description: string;
}

export interface VirusTotalResponse {
  data: {
    attributes: {
      last_analysis_stats: {
        malicious: number;
        suspicious: number;
        undetected: number;
        harmless: number;
      };
      reputation: number;
      last_analysis_date: number;
    };
  };
}

export interface MISPEvent {
  id: string;
  info: string;
  threat_level_id: string;
  analysis: string;
  timestamp: string;
  attributes: Array<{
    type: string;
    value: string;
    category: string;
    to_ids: boolean;
  }>;
}

// Mock VirusTotal API integration
export class VirusTotalService {
  private static instance: VirusTotalService;
  private apiKey: string = 'mock_vt_api_key';
  private baseUrl: string = 'https://www.virustotal.com/api/v3';

  public static getInstance(): VirusTotalService {
    if (!VirusTotalService.instance) {
      VirusTotalService.instance = new VirusTotalService();
    }
    return VirusTotalService.instance;
  }

  async scanURL(url: string): Promise<VirusTotalResponse> {
    // Mock VirusTotal response
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    const isSuspicious = url.includes('phish') || url.includes('malicious') || url.includes('scam');
    const isDangerous = url.includes('malware') || url.includes('virus') || url.includes('trojan');
    
    return {
      data: {
        attributes: {
          last_analysis_stats: {
            malicious: isDangerous ? Math.floor(Math.random() * 20) + 10 : isSuspicious ? Math.floor(Math.random() * 5) + 1 : 0,
            suspicious: isSuspicious ? Math.floor(Math.random() * 10) + 5 : Math.floor(Math.random() * 3),
            undetected: Math.floor(Math.random() * 30) + 20,
            harmless: Math.floor(Math.random() * 40) + 30
          },
          reputation: isDangerous ? -50 : isSuspicious ? -10 : Math.floor(Math.random() * 20),
          last_analysis_date: Date.now() / 1000
        }
      }
    };
  }

  async scanFile(fileHash: string): Promise<VirusTotalResponse> {
    // Mock file scan response
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    const isMalicious = fileHash.includes('malware') || fileHash.includes('virus');
    
    return {
      data: {
        attributes: {
          last_analysis_stats: {
            malicious: isMalicious ? Math.floor(Math.random() * 15) + 5 : 0,
            suspicious: Math.floor(Math.random() * 5),
            undetected: Math.floor(Math.random() * 25) + 15,
            harmless: Math.floor(Math.random() * 35) + 25
          },
          reputation: isMalicious ? -80 : Math.floor(Math.random() * 30),
          last_analysis_date: Date.now() / 1000
        }
      }
    };
  }
}

// Mock MISP (Malware Information Sharing Platform) integration
export class MISPService {
  private static instance: MISPService;
  private apiKey: string = 'mock_misp_api_key';
  private baseUrl: string = 'https://misp.example.com';

  public static getInstance(): MISPService {
    if (!MISPService.instance) {
      MISPService.instance = new MISPService();
    }
    return MISPService.instance;
  }

  async searchIndicators(value: string, type: string): Promise<ThreatIndicator[]> {
    // Mock MISP search
    await new Promise(resolve => setTimeout(resolve, 800));
    
    const mockIndicators: ThreatIndicator[] = [];
    
    if (value.includes('malicious') || value.includes('phish') || value.includes('scam')) {
      mockIndicators.push({
        id: `misp_${Date.now()}`,
        type: type as any,
        value,
        confidence: Math.floor(Math.random() * 30) + 70,
        source: 'MISP Community',
        firstSeen: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
        lastSeen: new Date(),
        tags: ['phishing', 'malicious', 'threat-actor'],
        description: 'Known malicious indicator from threat intelligence feeds'
      });
    }
    
    return mockIndicators;
  }

  async getLatestEvents(): Promise<MISPEvent[]> {
    // Mock latest MISP events
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    return [
      {
        id: '1',
        info: 'APT29 Campaign - Phishing Infrastructure',
        threat_level_id: '1',
        analysis: '2',
        timestamp: new Date().toISOString(),
        attributes: [
          {
            type: 'domain',
            value: 'malicious-domain.com',
            category: 'Network activity',
            to_ids: true
          }
        ]
      },
      {
        id: '2',
        info: 'Ransomware C2 Infrastructure',
        threat_level_id: '2',
        analysis: '1',
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        attributes: [
          {
            type: 'ip-dst',
            value: '192.168.1.100',
            category: 'Network activity',
            to_ids: true
          }
        ]
      }
    ];
  }
}

// Anomaly Detection Engine
export class AnomalyDetectionEngine {
  private static instance: AnomalyDetectionEngine;
  private baselineMetrics: Map<string, number[]> = new Map();

  public static getInstance(): AnomalyDetectionEngine {
    if (!AnomalyDetectionEngine.instance) {
      AnomalyDetectionEngine.instance = new AnomalyDetectionEngine();
    }
    return AnomalyDetectionEngine.instance;
  }

  // Statistical anomaly detection using Z-score
  detectAnomalies(metric: string, value: number, threshold: number = 2.5): boolean {
    const history = this.baselineMetrics.get(metric) || [];
    
    if (history.length < 10) {
      // Not enough data for anomaly detection
      history.push(value);
      this.baselineMetrics.set(metric, history);
      return false;
    }

    const mean = history.reduce((sum, val) => sum + val, 0) / history.length;
    const variance = history.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / history.length;
    const stdDev = Math.sqrt(variance);
    
    const zScore = Math.abs((value - mean) / stdDev);
    
    // Update history (sliding window)
    history.push(value);
    if (history.length > 100) {
      history.shift();
    }
    this.baselineMetrics.set(metric, history);
    
    return zScore > threshold;
  }

  // Behavioral analysis for user patterns
  analyzeBehaviorPattern(userId: string, action: string, timestamp: Date): {
    isAnomalous: boolean;
    confidence: number;
    reason: string;
  } {
    // Mock behavioral analysis
    const hour = timestamp.getHours();
    const isOffHours = hour < 6 || hour > 22;
    const isWeekend = timestamp.getDay() === 0 || timestamp.getDay() === 6;
    
    let anomalyScore = 0;
    let reasons: string[] = [];
    
    if (isOffHours) {
      anomalyScore += 0.3;
      reasons.push('Activity during off-hours');
    }
    
    if (isWeekend) {
      anomalyScore += 0.2;
      reasons.push('Weekend activity');
    }
    
    if (action.includes('admin') || action.includes('delete')) {
      anomalyScore += 0.4;
      reasons.push('High-privilege action');
    }
    
    return {
      isAnomalous: anomalyScore > 0.5,
      confidence: Math.min(anomalyScore * 100, 95),
      reason: reasons.join(', ')
    };
  }
}

// Signature-based detection engine
export class SignatureEngine {
  private static instance: SignatureEngine;
  private signatures: Map<string, RegExp[]> = new Map();

  public static getInstance(): SignatureEngine {
    if (!SignatureEngine.instance) {
      SignatureEngine.instance = new SignatureEngine();
      SignatureEngine.instance.loadSignatures();
    }
    return SignatureEngine.instance;
  }

  private loadSignatures(): void {
    // Load malware signatures
    this.signatures.set('malware', [
      /eval\s*\(\s*base64_decode/i,
      /document\.write\s*\(\s*unescape/i,
      /String\.fromCharCode\s*\(\s*\d+/i,
      /\$_POST\s*\[\s*['"]\w+['"]\s*\]/i
    ]);

    // Load phishing signatures
    this.signatures.set('phishing', [
      /urgent.*verify.*account/i,
      /suspended.*click.*here/i,
      /winner.*claim.*prize/i,
      /security.*alert.*login/i
    ]);

    // Load network attack signatures
    this.signatures.set('network', [
      /union.*select.*from/i,
      /<script.*>.*<\/script>/i,
      /javascript:.*alert/i,
      /\.\.\//g
    ]);
  }

  detectThreats(content: string, type: string = 'all'): {
    detected: boolean;
    matches: string[];
    confidence: number;
  } {
    const matches: string[] = [];
    
    const signaturesToCheck = type === 'all' 
      ? Array.from(this.signatures.values()).flat()
      : this.signatures.get(type) || [];

    for (const signature of signaturesToCheck) {
      if (signature.test(content)) {
        matches.push(signature.source);
      }
    }

    return {
      detected: matches.length > 0,
      matches,
      confidence: Math.min(matches.length * 25, 95)
    };
  }
}

// Threat Intelligence Aggregator
export class ThreatIntelligenceAggregator {
  private virusTotal: VirusTotalService;
  private misp: MISPService;
  private anomalyEngine: AnomalyDetectionEngine;
  private signatureEngine: SignatureEngine;

  constructor() {
    this.virusTotal = VirusTotalService.getInstance();
    this.misp = MISPService.getInstance();
    this.anomalyEngine = AnomalyDetectionEngine.getInstance();
    this.signatureEngine = SignatureEngine.getInstance();
  }

  async analyzeURL(url: string): Promise<{
    riskLevel: 'safe' | 'suspicious' | 'dangerous';
    confidence: number;
    sources: string[];
    details: any;
  }> {
    const results = await Promise.all([
      this.virusTotal.scanURL(url),
      this.misp.searchIndicators(url, 'url'),
      Promise.resolve(this.signatureEngine.detectThreats(url, 'phishing'))
    ]);

    const [vtResult, mispIndicators, signatureResult] = results;
    
    let riskScore = 0;
    const sources: string[] = [];
    
    // VirusTotal analysis
    if (vtResult.data.attributes.last_analysis_stats.malicious > 0) {
      riskScore += 0.4;
      sources.push('VirusTotal');
    }
    
    // MISP indicators
    if (mispIndicators.length > 0) {
      riskScore += 0.3;
      sources.push('MISP');
    }
    
    // Signature detection
    if (signatureResult.detected) {
      riskScore += 0.3;
      sources.push('Signature Engine');
    }
    
    let riskLevel: 'safe' | 'suspicious' | 'dangerous';
    if (riskScore >= 0.7) {
      riskLevel = 'dangerous';
    } else if (riskScore >= 0.3) {
      riskLevel = 'suspicious';
    } else {
      riskLevel = 'safe';
    }
    
    return {
      riskLevel,
      confidence: Math.min(riskScore * 100, 95),
      sources,
      details: {
        virusTotal: vtResult,
        mispIndicators,
        signatures: signatureResult
      }
    };
  }

  async analyzeFile(fileHash: string, content?: string): Promise<{
    riskLevel: 'safe' | 'suspicious' | 'dangerous';
    confidence: number;
    sources: string[];
    details: any;
  }> {
    const results = await Promise.all([
      this.virusTotal.scanFile(fileHash),
      this.misp.searchIndicators(fileHash, 'hash'),
      content ? Promise.resolve(this.signatureEngine.detectThreats(content, 'malware')) : Promise.resolve({ detected: false, matches: [], confidence: 0 })
    ]);

    const [vtResult, mispIndicators, signatureResult] = results;
    
    let riskScore = 0;
    const sources: string[] = [];
    
    // VirusTotal analysis
    if (vtResult.data.attributes.last_analysis_stats.malicious > 0) {
      riskScore += 0.5;
      sources.push('VirusTotal');
    }
    
    // MISP indicators
    if (mispIndicators.length > 0) {
      riskScore += 0.3;
      sources.push('MISP');
    }
    
    // Signature detection
    if (signatureResult.detected) {
      riskScore += 0.4;
      sources.push('Signature Engine');
    }
    
    let riskLevel: 'safe' | 'suspicious' | 'dangerous';
    if (riskScore >= 0.7) {
      riskLevel = 'dangerous';
    } else if (riskScore >= 0.3) {
      riskLevel = 'suspicious';
    } else {
      riskLevel = 'safe';
    }
    
    return {
      riskLevel,
      confidence: Math.min(riskScore * 100, 95),
      sources,
      details: {
        virusTotal: vtResult,
        mispIndicators,
        signatures: signatureResult
      }
    };
  }
}

// Export singleton instance
export const threatIntelligence = new ThreatIntelligenceAggregator();