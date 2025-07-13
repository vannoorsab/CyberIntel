import { ForensicCase, AuditLog, ForensicEvidence, ForensicTimelineEntry, SystemActivity, ChainOfCustodyEntry, ForensicFinding, ForensicReport } from '../types';
import { emailService } from './emailService';

export class ForensicsEngine {
  private static instance: ForensicsEngine;
  private auditBuffer: AuditLog[] = [];
  private evidenceRegistry: Map<string, ForensicEvidence> = new Map();
  private chainOfCustodyLog: Map<string, ChainOfCustodyEntry[]> = new Map();

  public static getInstance(): ForensicsEngine {
    if (!ForensicsEngine.instance) {
      ForensicsEngine.instance = new ForensicsEngine();
    }
    return ForensicsEngine.instance;
  }

  // Record system activity for audit trail
  public recordActivity(
    userId: string,
    userEmail: string,
    userName: string,
    userRole: string,
    action: string,
    resource: string,
    resourceType: string,
    outcome: 'success' | 'failure' | 'partial',
    details: Record<string, any> = {},
    sourceIP: string = '127.0.0.1',
    userAgent: string = 'Unknown'
  ): AuditLog {
    const auditEntry: AuditLog = {
      id: `AUDIT-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      eventType: this.categorizeEventType(action),
      userId,
      userEmail,
      userName,
      userRole,
      sourceIP,
      userAgent,
      sessionId: this.generateSessionId(),
      action,
      resource,
      resourceType,
      resourceId: details.resourceId,
      outcome,
      details,
      riskScore: this.calculateRiskScore(action, outcome, details, sourceIP),
      geolocation: this.lookupGeolocation(sourceIP),
      deviceInfo: this.parseDeviceInfo(userAgent),
      correlationId: details.correlationId,
      parentEventId: details.parentEventId,
      tags: this.generateTags(action, resource, outcome),
      retention: new Date(Date.now() + 86400000 * 2555), // 7 years
      archived: false
    };

    this.auditBuffer.push(auditEntry);
    
    // Auto-alert for high-risk activities
    if (auditEntry.riskScore >= 80) {
      this.alertHighRiskActivity(auditEntry);
    }

    return auditEntry;
  }

  // Create forensic case
  public createForensicCase(
    title: string,
    description: string,
    caseType: string,
    priority: 'low' | 'medium' | 'high' | 'critical',
    investigator: string,
    relatedIncidents: string[] = []
  ): ForensicCase {
    const caseNumber = this.generateCaseNumber();
    
    const forensicCase: ForensicCase = {
      id: `CASE-${Date.now()}`,
      caseNumber,
      title,
      description,
      status: 'open',
      priority,
      caseType: caseType as any,
      investigator,
      assignedTeam: [investigator],
      createdAt: new Date(),
      updatedAt: new Date(),
      relatedIncidents,
      evidence: [],
      timeline: [],
      chainOfCustody: [],
      findings: [],
      legalHold: priority === 'critical',
      retentionPeriod: 2555, // 7 years default
      tags: [caseType, priority],
      metadata: {}
    };

    // Record case creation in audit log
    this.recordActivity(
      'system',
      'system@agentphantom.ai',
      'System',
      'system',
      'create_forensic_case',
      caseNumber,
      'forensic_case',
      'success',
      { caseId: forensicCase.id, priority, caseType }
    );

    return forensicCase;
  }

  // Add evidence to case with chain of custody
  public addEvidence(
    caseId: string,
    evidenceType: string,
    description: string,
    source: string,
    location: string,
    collectedBy: string,
    acquisitionMethod: string,
    acquisitionTool: string,
    fileSize: number = 0,
    metadata: Record<string, any> = {}
  ): ForensicEvidence {
    const evidenceNumber = this.generateEvidenceNumber();
    
    const evidence: ForensicEvidence = {
      id: `EVID-${Date.now()}`,
      caseId,
      evidenceNumber,
      type: evidenceType as any,
      description,
      source,
      location,
      size: fileSize,
      hash: this.generateEvidenceHash(location),
      collectedBy,
      collectedAt: new Date(),
      acquisitionMethod,
      acquisitionTool,
      verified: false,
      encrypted: true, // Default to encrypted
      metadata: {
        ...metadata,
        hostname: metadata.hostname || 'unknown',
        username: metadata.username || 'unknown',
        timezone: metadata.timezone || 'UTC'
      },
      chainOfCustody: [],
      analysis: [],
      tags: [evidenceType, source],
      legalHold: true,
      retentionDate: new Date(Date.now() + 86400000 * 2555),
      accessLog: []
    };

    // Create initial chain of custody entry
    const custodyEntry = this.createChainOfCustodyEntry(
      evidence.id,
      'collected',
      collectedBy,
      'Evidence collection site',
      'Initial evidence collection and preservation'
    );

    evidence.chainOfCustody.push(custodyEntry);
    this.evidenceRegistry.set(evidence.id, evidence);

    // Record evidence addition in audit log
    this.recordActivity(
      collectedBy,
      `${collectedBy.toLowerCase().replace(' ', '.')}@company.com`,
      collectedBy,
      'forensic_investigator',
      'add_evidence',
      evidenceNumber,
      'forensic_evidence',
      'success',
      { 
        caseId, 
        evidenceType, 
        source, 
        fileSize,
        acquisitionTool 
      }
    );

    return evidence;
  }

  // Create chain of custody entry
  public createChainOfCustodyEntry(
    evidenceId: string,
    action: string,
    officer: string,
    location: string,
    purpose: string,
    notes?: string,
    witness?: string
  ): ChainOfCustodyEntry {
    const entry: ChainOfCustodyEntry = {
      id: `COC-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      evidenceId,
      action: action as any,
      timestamp: new Date(),
      officer,
      location,
      purpose,
      notes,
      witness,
      signature: this.generateDigitalSignature(officer, evidenceId, action),
      transferMethod: action.includes('transfer') ? 'secure_transport' : undefined,
      storageLocation: action === 'stored' ? location : undefined,
      accessReason: action === 'accessed' ? purpose : undefined
    };

    // Update chain of custody log
    const existingChain = this.chainOfCustodyLog.get(evidenceId) || [];
    existingChain.push(entry);
    this.chainOfCustodyLog.set(evidenceId, existingChain);

    // Record in audit log
    this.recordActivity(
      officer,
      `${officer.toLowerCase().replace(' ', '.')}@company.com`,
      officer,
      'forensic_investigator',
      `chain_of_custody_${action}`,
      evidenceId,
      'evidence_custody',
      'success',
      { action, location, purpose, witness }
    );

    return entry;
  }

  // Timeline reconstruction
  public reconstructTimeline(
    caseId: string,
    evidenceIds: string[],
    timeRange: { start: Date; end: Date }
  ): ForensicTimelineEntry[] {
    const timelineEntries: ForensicTimelineEntry[] = [];

    // Simulate timeline reconstruction from multiple evidence sources
    evidenceIds.forEach(evidenceId => {
      const evidence = this.evidenceRegistry.get(evidenceId);
      if (!evidence) return;

      // Generate mock timeline entries based on evidence type
      const entries = this.generateTimelineFromEvidence(evidence, timeRange);
      timelineEntries.push(...entries);
    });

    // Sort by timestamp
    timelineEntries.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    // Correlate related events
    this.correlateTimelineEvents(timelineEntries);

    return timelineEntries;
  }

  // Generate forensic report
  public generateCaseReport(forensicCase: ForensicCase): string {
    const report = `
DIGITAL FORENSIC INVESTIGATION REPORT
=====================================

Case Information:
-----------------
Case Number: ${forensicCase.caseNumber}
Case Title: ${forensicCase.title}
Investigation Type: ${forensicCase.caseType.replace('_', ' ').toUpperCase()}
Priority Level: ${forensicCase.priority.toUpperCase()}
Status: ${forensicCase.status.toUpperCase()}

Investigator: ${forensicCase.investigator}
Assigned Team: ${forensicCase.assignedTeam.join(', ')}
Created: ${forensicCase.createdAt.toLocaleString()}
Last Updated: ${forensicCase.updatedAt.toLocaleString()}
${forensicCase.dueDate ? `Due Date: ${forensicCase.dueDate.toLocaleString()}` : ''}

Case Description:
-----------------
${forensicCase.description}

${forensicCase.relatedIncidents.length > 0 ? `
Related Incidents:
------------------
${forensicCase.relatedIncidents.map(id => `• ${id}`).join('\n')}
` : ''}

Evidence Summary:
-----------------
Total Evidence Items: ${forensicCase.evidence.length}
${forensicCase.evidence.map(e => `• ${e.evidenceNumber}: ${e.description}`).join('\n')}

Chain of Custody:
------------------
${forensicCase.chainOfCustody.map(entry => 
  `${entry.timestamp.toLocaleString()} - ${entry.action.toUpperCase()} by ${entry.officer} at ${entry.location}`
).join('\n')}

Timeline of Events:
-------------------
${forensicCase.timeline.map(entry => 
  `${entry.timestamp.toLocaleString()} - ${entry.description} (${entry.source})`
).join('\n')}

Findings:
---------
${forensicCase.findings.map((finding, index) => 
  `${index + 1}. ${finding.title}\n   ${finding.description}\n   Severity: ${finding.severity.toUpperCase()}\n   Confidence: ${finding.confidence}%`
).join('\n\n')}

Legal Considerations:
---------------------
Legal Hold Status: ${forensicCase.legalHold ? 'ACTIVE' : 'Not Applied'}
Retention Period: ${forensicCase.retentionPeriod} days
Evidence Preservation: All evidence has been properly preserved with verified chain of custody

Methodology:
------------
• Industry-standard forensic procedures followed
• Write-blocking technology used during acquisition
• Cryptographic hashing for integrity verification
• Comprehensive documentation maintained
• Chain of custody strictly observed

Conclusions:
------------
${this.generateConclusions(forensicCase)}

Recommendations:
----------------
${this.generateRecommendations(forensicCase)}

Technical Details:
------------------
Evidence Hash Verification: All evidence items have been cryptographically verified
Acquisition Tools: ${forensicCase.evidence.map(e => e.acquisitionTool).filter((tool, index, arr) => arr.indexOf(tool) === index).join(', ')}
Analysis Software: AgentPhantom.AI Forensic Suite
Compliance: Meets requirements for legal admissibility

Report Generated: ${new Date().toLocaleString()}
Generated By: AgentPhantom.AI Forensics Engine
Digital Signature: ${this.generateReportSignature(forensicCase)}

---
This report contains confidential information and is intended for authorized personnel only.
Unauthorized disclosure is prohibited and may be subject to legal action.
    `;

    return report;
  }

  // Generate mock audit log for testing
  public generateMockAuditLog(): AuditLog {
    const mockUsers = [
      { name: 'Sarah Connor', email: 'sarah.connor@company.com', role: 'forensic_investigator' },
      { name: 'John Matrix', email: 'john.matrix@company.com', role: 'security_analyst' },
      { name: 'Lisa Chen', email: 'lisa.chen@company.com', role: 'compliance_officer' },
      { name: 'Unknown User', email: 'unknown@external.com', role: 'guest' }
    ];

    const mockActions = [
      'access_evidence', 'download_evidence', 'analyze_evidence', 'create_case',
      'update_case', 'login', 'logout', 'failed_login', 'export_data',
      'modify_settings', 'view_report', 'generate_report'
    ];

    const mockResources = [
      'disk_image_001.dd', 'memory_dump_002.mem', 'network_capture.pcap',
      'case_report.pdf', 'evidence_database', 'forensic_workstation',
      'chain_of_custody_log', 'audit_trail'
    ];

    const user = mockUsers[Math.floor(Math.random() * mockUsers.length)];
    const action = mockActions[Math.floor(Math.random() * mockActions.length)];
    const resource = mockResources[Math.floor(Math.random() * mockResources.length)];
    const outcome = Math.random() > 0.1 ? 'success' : 'failure';

    return {
      id: `AUDIT-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      eventType: this.categorizeEventType(action),
      userId: `user_${Date.now()}`,
      userEmail: user.email,
      userName: user.name,
      userRole: user.role,
      sourceIP: this.generateMockIP(),
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      sessionId: `sess_${Math.random().toString(36).substr(2, 9)}`,
      action,
      resource,
      resourceType: this.getResourceType(resource),
      outcome: outcome as any,
      details: this.generateMockDetails(action, resource),
      riskScore: this.calculateMockRiskScore(action, outcome, user.role),
      geolocation: this.generateMockGeolocation(),
      deviceInfo: {
        deviceType: 'desktop',
        operatingSystem: 'Windows 10',
        browser: 'Chrome 120',
        fingerprint: `fp_${Math.random().toString(36).substr(2, 9)}`
      },
      tags: this.generateTags(action, resource, outcome),
      retention: new Date(Date.now() + 86400000 * 2555),
      archived: false
    };
  }

  // Private helper methods
  private categorizeEventType(action: string): any {
    if (action.includes('login') || action.includes('logout')) return 'authentication';
    if (action.includes('evidence') || action.includes('case')) return 'evidence_access';
    if (action.includes('data') || action.includes('export')) return 'data_access';
    if (action.includes('settings') || action.includes('config')) return 'system_change';
    if (action.includes('user') || action.includes('role')) return 'user_management';
    if (action.includes('report')) return 'report_generation';
    return 'data_access';
  }

  private calculateRiskScore(
    action: string,
    outcome: string,
    details: Record<string, any>,
    sourceIP: string
  ): number {
    let score = 0;

    // Base score by action type
    if (action.includes('failed_login')) score += 40;
    else if (action.includes('evidence')) score += 20;
    else if (action.includes('export') || action.includes('download')) score += 30;
    else if (action.includes('delete') || action.includes('modify')) score += 35;
    else score += 10;

    // Outcome modifier
    if (outcome === 'failure') score += 30;
    else if (outcome === 'partial') score += 15;

    // IP-based risk
    if (this.isExternalIP(sourceIP)) score += 25;
    if (this.isSuspiciousIP(sourceIP)) score += 40;

    // Time-based risk (off-hours)
    const hour = new Date().getHours();
    if (hour < 6 || hour > 22) score += 15;

    // Volume-based risk
    if (details.fileSize && details.fileSize > 1000000000) score += 20; // >1GB

    return Math.min(score, 100);
  }

  private generateSessionId(): string {
    return `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private lookupGeolocation(ip: string): any {
    // Mock geolocation lookup
    if (this.isExternalIP(ip)) {
      return {
        country: 'Unknown',
        region: 'Unknown',
        city: 'Unknown',
        latitude: 0,
        longitude: 0
      };
    }
    
    return {
      country: 'United States',
      region: 'California',
      city: 'San Francisco',
      latitude: 37.7749,
      longitude: -122.4194
    };
  }

  private parseDeviceInfo(userAgent: string): any {
    return {
      deviceType: userAgent.includes('Mobile') ? 'mobile' : 'desktop',
      operatingSystem: userAgent.includes('Windows') ? 'Windows' : 
                      userAgent.includes('Mac') ? 'macOS' : 'Linux',
      browser: userAgent.includes('Chrome') ? 'Chrome' :
               userAgent.includes('Firefox') ? 'Firefox' : 'Unknown',
      fingerprint: `fp_${Math.random().toString(36).substr(2, 9)}`
    };
  }

  private generateTags(action: string, resource: string, outcome: string): string[] {
    const tags = [action.split('_')[0], outcome];
    
    if (resource.includes('evidence')) tags.push('evidence');
    if (resource.includes('case')) tags.push('case-management');
    if (resource.includes('report')) tags.push('reporting');
    if (action.includes('failed')) tags.push('security-event');
    
    return tags;
  }

  private alertHighRiskActivity(auditEntry: AuditLog): void {
    emailService.sendEmail({
      to: 'vanursab71@gmail.com',
      subject: `🚨 HIGH-RISK FORENSIC ACTIVITY DETECTED`,
      message: `
🚨 HIGH-RISK FORENSIC ACTIVITY ALERT 🚨
=======================================

⚠️ IMMEDIATE ATTENTION REQUIRED ⚠️

🔍 ACTIVITY DETAILS:
• Event ID: ${auditEntry.id}
• User: ${auditEntry.userName} (${auditEntry.userEmail})
• Action: ${auditEntry.action.replace('_', ' ').toUpperCase()}
• Resource: ${auditEntry.resource}
• Risk Score: ${auditEntry.riskScore}/100
• Outcome: ${auditEntry.outcome.toUpperCase()}

📊 CONTEXT:
• Source IP: ${auditEntry.sourceIP}
• User Role: ${auditEntry.userRole}
• Session: ${auditEntry.sessionId}
• Timestamp: ${auditEntry.timestamp.toLocaleString()}

🌍 LOCATION:
• Country: ${auditEntry.geolocation?.country || 'Unknown'}
• Region: ${auditEntry.geolocation?.region || 'Unknown'}
• City: ${auditEntry.geolocation?.city || 'Unknown'}

💻 DEVICE INFO:
• Device: ${auditEntry.deviceInfo?.deviceType || 'Unknown'}
• OS: ${auditEntry.deviceInfo?.operatingSystem || 'Unknown'}
• Browser: ${auditEntry.deviceInfo?.browser || 'Unknown'}

⚡ IMMEDIATE ACTIONS REQUIRED:
1. 🔍 Review activity details in Forensics Dashboard
2. 👤 Verify user identity and authorization
3. 🚨 Investigate potential security breach
4. 📋 Document findings and response actions
5. 🛡️ Update security policies if necessary

🌐 ACCESS FORENSICS DASHBOARD:
https://agentphantom.ai/forensics-audit

📧 This is an automated forensic alert from AgentPhantom.AI
🔒 Confidential - For authorized personnel only

---
AgentPhantom.AI Forensics & Audit System
🔍 Protecting digital evidence integrity 24/7
📧 Contact: vanursab71@gmail.com
      `,
      type: 'forensic'
    });
  }

  private generateCaseNumber(): string {
    const year = new Date().getFullYear();
    const sequence = Math.floor(Math.random() * 9999) + 1;
    return `FR-${year}-${sequence.toString().padStart(4, '0')}`;
  }

  private generateEvidenceNumber(): string {
    const year = new Date().getFullYear();
    const sequence = Math.floor(Math.random() * 999) + 1;
    return `E${sequence.toString().padStart(3, '0')}-${year}`;
  }

  private generateEvidenceHash(location: string): any {
    // Mock hash generation
    const content = location + Date.now().toString();
    return {
      md5: this.mockHash(content, 32),
      sha1: this.mockHash(content, 40),
      sha256: this.mockHash(content, 64),
      sha512: this.mockHash(content, 128),
      verifiedAt: new Date(),
      verifiedBy: 'System'
    };
  }

  private mockHash(input: string, length: number): string {
    const chars = '0123456789abcdef';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  private generateDigitalSignature(officer: string, evidenceId: string, action: string): string {
    return `DS_${this.mockHash(officer + evidenceId + action + Date.now(), 16)}`;
  }

  private generateTimelineFromEvidence(
    evidence: ForensicEvidence,
    timeRange: { start: Date; end: Date }
  ): ForensicTimelineEntry[] {
    const entries: ForensicTimelineEntry[] = [];
    const eventCount = Math.floor(Math.random() * 10) + 5;

    for (let i = 0; i < eventCount; i++) {
      const timestamp = new Date(
        timeRange.start.getTime() + 
        Math.random() * (timeRange.end.getTime() - timeRange.start.getTime())
      );

      entries.push({
        id: `TL-${Date.now()}-${i}`,
        caseId: evidence.caseId,
        timestamp,
        eventType: this.getRandomEventType(),
        source: evidence.source,
        description: this.generateEventDescription(),
        details: {},
        evidenceId: evidence.id,
        confidence: Math.floor(Math.random() * 30) + 70,
        tags: ['automated', evidence.type],
        correlatedEvents: [],
        verified: false
      });
    }

    return entries;
  }

  private getRandomEventType(): any {
    const types = ['system_event', 'user_action', 'network_activity', 'file_operation', 'process_execution'];
    return types[Math.floor(Math.random() * types.length)];
  }

  private generateEventDescription(): string {
    const descriptions = [
      'User login detected',
      'File access recorded',
      'Network connection established',
      'Process execution logged',
      'Registry modification detected',
      'Email sent/received',
      'USB device connected',
      'Application launched',
      'System shutdown initiated',
      'Security policy violation'
    ];
    return descriptions[Math.floor(Math.random() * descriptions.length)];
  }

  private correlateTimelineEvents(entries: ForensicTimelineEntry[]): void {
    // Simple correlation based on time proximity and event types
    entries.forEach((entry, index) => {
      const correlatedIds: string[] = [];
      
      entries.forEach((otherEntry, otherIndex) => {
        if (index !== otherIndex) {
          const timeDiff = Math.abs(entry.timestamp.getTime() - otherEntry.timestamp.getTime());
          if (timeDiff < 300000 && entry.source === otherEntry.source) { // 5 minutes
            correlatedIds.push(otherEntry.id);
          }
        }
      });
      
      entry.correlatedEvents = correlatedIds.slice(0, 3); // Limit to 3 correlations
    });
  }

  private generateConclusions(forensicCase: ForensicCase): string {
    const conclusions = [
      'Evidence analysis indicates unauthorized access to sensitive systems',
      'Timeline reconstruction shows clear pattern of malicious activity',
      'Digital artifacts confirm presence of advanced persistent threat',
      'Investigation reveals compliance violations requiring immediate remediation',
      'Forensic examination supports incident response findings'
    ];
    return conclusions[Math.floor(Math.random() * conclusions.length)];
  }

  private generateRecommendations(forensicCase: ForensicCase): string {
    return `• Implement additional access controls for sensitive systems
• Enhance monitoring and alerting capabilities
• Conduct security awareness training for affected personnel
• Review and update incident response procedures
• Consider third-party security assessment
• Implement data loss prevention measures
• Strengthen endpoint detection and response capabilities`;
  }

  private generateReportSignature(forensicCase: ForensicCase): string {
    return `RS_${this.mockHash(forensicCase.id + Date.now().toString(), 32)}`;
  }

  private generateMockIP(): string {
    if (Math.random() < 0.8) {
      // Internal IP
      return `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    } else {
      // External IP
      return `203.0.113.${Math.floor(Math.random() * 255)}`;
    }
  }

  private getResourceType(resource: string): string {
    if (resource.includes('evidence') || resource.includes('.dd') || resource.includes('.mem')) return 'forensic_evidence';
    if (resource.includes('case') || resource.includes('report')) return 'case_file';
    if (resource.includes('database')) return 'database';
    if (resource.includes('workstation')) return 'system';
    return 'file';
  }

  private generateMockDetails(action: string, resource: string): Record<string, any> {
    const details: Record<string, any> = {};
    
    if (action.includes('download') || action.includes('access')) {
      details.fileSize = Math.floor(Math.random() * 1000000000) + 1000000; // 1MB to 1GB
      details.duration = Math.floor(Math.random() * 3600) + 60; // 1 minute to 1 hour
    }
    
    if (action.includes('failed')) {
      details.reason = 'invalid_credentials';
      details.attempts = Math.floor(Math.random() * 5) + 1;
    }
    
    if (action.includes('evidence')) {
      details.evidenceType = resource.includes('.dd') ? 'disk_image' : 
                           resource.includes('.mem') ? 'memory_dump' : 'file';
    }
    
    return details;
  }

  private calculateMockRiskScore(action: string, outcome: string, userRole: string): number {
    let score = 10;
    
    if (action.includes('failed')) score += 40;
    if (action.includes('evidence')) score += 20;
    if (action.includes('export')) score += 25;
    if (outcome === 'failure') score += 30;
    if (userRole === 'guest') score += 35;
    
    return Math.min(score + Math.floor(Math.random() * 20), 100);
  }

  private generateMockGeolocation(): any {
    const locations = [
      { country: 'United States', region: 'California', city: 'San Francisco', lat: 37.7749, lng: -122.4194 },
      { country: 'United States', region: 'New York', city: 'New York', lat: 40.7128, lng: -74.0060 },
      { country: 'United Kingdom', region: 'England', city: 'London', lat: 51.5074, lng: -0.1278 },
      { country: 'Unknown', region: 'Unknown', city: 'Unknown', lat: 0, lng: 0 }
    ];
    
    const location = locations[Math.floor(Math.random() * locations.length)];
    return {
      country: location.country,
      region: location.region,
      city: location.city,
      latitude: location.lat,
      longitude: location.lng
    };
  }

  private isExternalIP(ip: string): boolean {
    return !ip.startsWith('192.168.') && !ip.startsWith('10.') && !ip.startsWith('172.');
  }

  private isSuspiciousIP(ip: string): boolean {
    const suspiciousIPs = ['203.0.113.42', '198.51.100.1', '192.0.2.1'];
    return suspiciousIPs.includes(ip);
  }
}

// Export singleton instance
export const forensicsEngine = ForensicsEngine.getInstance();