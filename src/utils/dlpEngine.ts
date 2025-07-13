import { DLPViolation, DLPPolicy, DataClassification, DLPMatch, DLPFileInfo, DLPEvidence } from '../types';
import { emailService } from './emailService';

export class DLPEngine {
  private static instance: DLPEngine;
  private policies: Map<string, DLPPolicy> = new Map();
  private dataClassifications: Map<string, DataClassification> = new Map();
  private violationHistory: DLPViolation[] = [];

  public static getInstance(): DLPEngine {
    if (!DLPEngine.instance) {
      DLPEngine.instance = new DLPEngine();
    }
    return DLPEngine.instance;
  }

  constructor() {
    this.loadDefaultClassifications();
    this.loadDefaultPolicies();
  }

  // Load default data classifications
  private loadDefaultClassifications(): void {
    const classifications: DataClassification[] = [
      {
        id: 'SSN',
        name: 'Social Security Numbers',
        type: 'pii',
        patterns: [
          {
            pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
            description: 'SSN format XXX-XX-XXXX',
            confidence: 95,
            examples: ['123-45-6789', '987-65-4321']
          },
          {
            pattern: '\\b\\d{9}\\b',
            description: 'SSN without dashes',
            confidence: 85,
            examples: ['123456789', '987654321']
          }
        ],
        keywords: ['ssn', 'social security', 'social security number'],
        confidence: 95,
        sensitivity: 'restricted',
        description: 'US Social Security Numbers',
        examples: ['123-45-6789', '123456789'],
        regulatoryFramework: ['PII', 'GDPR', 'CCPA']
      },
      {
        id: 'CREDIT_CARD',
        name: 'Credit Card Numbers',
        type: 'pci',
        patterns: [
          {
            pattern: '\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b',
            description: 'Credit card number patterns (Visa, MC, Amex, Discover)',
            confidence: 90,
            examples: ['4111111111111111', '5555555555554444']
          }
        ],
        keywords: ['credit card', 'card number', 'visa', 'mastercard', 'amex', 'discover'],
        confidence: 90,
        sensitivity: 'restricted',
        description: 'Credit card numbers',
        examples: ['4111-1111-1111-1111', '5555 5555 5555 4444'],
        regulatoryFramework: ['PCI-DSS']
      },
      {
        id: 'EMAIL',
        name: 'Email Addresses',
        type: 'pii',
        patterns: [
          {
            pattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b',
            description: 'Email address format',
            confidence: 85,
            examples: ['user@example.com', 'test.email@domain.org']
          }
        ],
        keywords: ['email', 'e-mail', '@'],
        confidence: 85,
        sensitivity: 'internal',
        description: 'Email addresses',
        examples: ['user@example.com'],
        regulatoryFramework: ['GDPR', 'CCPA']
      },
      {
        id: 'PHONE',
        name: 'Phone Numbers',
        type: 'pii',
        patterns: [
          {
            pattern: '\\b(?:\\+?1[-. ]?)?\\(?([0-9]{3})\\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\\b',
            description: 'US phone number format',
            confidence: 80,
            examples: ['(555) 123-4567', '+1-555-123-4567']
          }
        ],
        keywords: ['phone', 'telephone', 'mobile', 'cell'],
        confidence: 80,
        sensitivity: 'internal',
        description: 'Phone numbers',
        examples: ['(555) 123-4567', '555-123-4567'],
        regulatoryFramework: ['GDPR', 'CCPA']
      },
      {
        id: 'MEDICAL_RECORD',
        name: 'Medical Record Numbers',
        type: 'phi',
        patterns: [
          {
            pattern: '\\bMRN[:\\s]*[0-9]{6,10}\\b',
            description: 'Medical Record Number format',
            confidence: 90,
            examples: ['MRN: 1234567', 'MRN 9876543210']
          }
        ],
        keywords: ['mrn', 'medical record', 'patient id', 'health record'],
        confidence: 90,
        sensitivity: 'restricted',
        description: 'Medical record numbers',
        examples: ['MRN: 1234567'],
        regulatoryFramework: ['HIPAA', 'HITECH']
      }
    ];

    classifications.forEach(classification => {
      this.dataClassifications.set(classification.id, classification);
    });
  }

  // Load default DLP policies
  private loadDefaultPolicies(): void {
    const policies: DLPPolicy[] = [
      {
        id: 'PII_PROTECTION',
        name: 'PII Protection Policy',
        description: 'Prevent unauthorized transfer of personally identifiable information',
        enabled: true,
        priority: 1,
        dataTypes: [],
        conditions: [],
        actions: [],
        channels: [],
        exceptions: [],
        createdBy: 'System',
        createdAt: new Date(),
        lastModified: new Date(),
        violationCount: 0,
        falsePositiveRate: 0
      }
    ];

    policies.forEach(policy => {
      this.policies.set(policy.id, policy);
    });
  }

  // Scan content for sensitive data
  public scanContent(content: string, context: string = 'unknown'): {
    violations: DLPMatch[];
    riskScore: number;
    dataTypes: string[];
  } {
    const violations: DLPMatch[] = [];
    const detectedTypes = new Set<string>();

    // Scan against all data classifications
    this.dataClassifications.forEach((classification, id) => {
      classification.patterns.forEach(pattern => {
        const regex = new RegExp(pattern.pattern, 'gi');
        const matches = content.match(regex);
        
        if (matches) {
          matches.forEach(match => {
            violations.push({
              dataType: classification.name,
              pattern: pattern.description,
              confidence: pattern.confidence,
              context: this.extractContext(content, match),
              location: context,
              count: 1
            });
            detectedTypes.add(classification.name);
          });
        }
      });

      // Check for keyword matches
      classification.keywords.forEach(keyword => {
        const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
        if (regex.test(content)) {
          // Lower confidence for keyword-only matches
          violations.push({
            dataType: classification.name,
            pattern: `Keyword: ${keyword}`,
            confidence: Math.max(classification.confidence - 20, 30),
            context: this.extractContext(content, keyword),
            location: context,
            count: 1
          });
          detectedTypes.add(classification.name);
        }
      });
    });

    // Calculate risk score
    const riskScore = this.calculateRiskScore(violations);

    return {
      violations,
      riskScore,
      dataTypes: Array.from(detectedTypes)
    };
  }

  // Extract context around a match
  private extractContext(content: string, match: string, contextLength: number = 50): string {
    const index = content.toLowerCase().indexOf(match.toLowerCase());
    if (index === -1) return match;

    const start = Math.max(0, index - contextLength);
    const end = Math.min(content.length, index + match.length + contextLength);
    
    return content.substring(start, end);
  }

  // Calculate risk score based on violations
  private calculateRiskScore(violations: DLPMatch[]): number {
    if (violations.length === 0) return 0;

    let totalScore = 0;
    let weightedCount = 0;

    violations.forEach(violation => {
      const baseScore = violation.confidence;
      let multiplier = 1;

      // Increase score for high-sensitivity data types
      if (violation.dataType.includes('SSN') || violation.dataType.includes('Credit Card')) {
        multiplier = 1.5;
      } else if (violation.dataType.includes('Medical') || violation.dataType.includes('Health')) {
        multiplier = 1.4;
      } else if (violation.dataType.includes('Financial')) {
        multiplier = 1.3;
      }

      totalScore += baseScore * multiplier;
      weightedCount += multiplier;
    });

    // Normalize to 0-100 scale
    const averageScore = totalScore / Math.max(weightedCount, 1);
    
    // Apply volume multiplier (more violations = higher risk)
    const volumeMultiplier = Math.min(1 + (violations.length - 1) * 0.1, 2.0);
    
    return Math.min(Math.round(averageScore * volumeMultiplier), 100);
  }

  // Process a potential DLP violation
  public async processViolation(
    content: string,
    userId: string,
    userEmail: string,
    userName: string,
    department: string,
    channel: string,
    destination?: string,
    fileInfo?: Partial<DLPFileInfo>
  ): Promise<DLPViolation | null> {
    const scanResult = this.scanContent(content, channel);
    
    if (scanResult.violations.length === 0) {
      return null; // No violations detected
    }

    // Determine severity based on risk score
    let severity: 'low' | 'medium' | 'high' | 'critical';
    if (scanResult.riskScore >= 90) severity = 'critical';
    else if (scanResult.riskScore >= 70) severity = 'high';
    else if (scanResult.riskScore >= 50) severity = 'medium';
    else severity = 'low';

    // Create violation record
    const violation: DLPViolation = {
      id: `VIO-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      policyId: 'PII_PROTECTION', // Default policy
      policyName: 'PII Protection Policy',
      severity,
      status: 'detected',
      userId,
      userEmail,
      userName,
      department,
      timestamp: new Date(),
      channel,
      dataTypes: scanResult.dataTypes,
      matchedContent: scanResult.violations,
      destination,
      fileInfo: fileInfo as DLPFileInfo,
      actionTaken: this.determineActions(severity, channel),
      falsePositive: false,
      riskScore: scanResult.riskScore,
      evidence: []
    };

    // Store violation
    this.violationHistory.push(violation);

    // Send notification for high-risk violations
    if (severity === 'critical' || severity === 'high') {
      await this.notifyDLPViolation(violation);
    }

    return violation;
  }

  // Determine appropriate actions based on severity and channel
  private determineActions(severity: string, channel: string): string[] {
    const actions: string[] = ['logged'];

    switch (severity) {
      case 'critical':
        actions.push('blocked', 'quarantined', 'notified_admin', 'notified_user');
        if (channel === 'email') actions.push('encrypted');
        break;
      case 'high':
        actions.push('blocked', 'notified_admin', 'notified_user');
        if (channel === 'email') actions.push('encrypted');
        break;
      case 'medium':
        actions.push('notified_user', 'requires_justification');
        break;
      case 'low':
        actions.push('monitored');
        break;
    }

    return actions;
  }

  // Generate mock violation for testing
  public generateMockViolation(): DLPViolation {
    const mockUsers = [
      { name: 'John Doe', email: 'john.doe@company.com', dept: 'Marketing' },
      { name: 'Jane Smith', email: 'jane.smith@company.com', dept: 'Finance' },
      { name: 'Bob Wilson', email: 'bob.wilson@company.com', dept: 'HR' },
      { name: 'Alice Johnson', email: 'alice.johnson@company.com', dept: 'Engineering' }
    ];

    const mockChannels = ['email', 'usb', 'cloud', 'web', 'network'];
    const mockDataTypes = ['PII', 'Financial Records', 'PHI', 'Credit Card', 'SSN'];
    const mockSeverities: ('low' | 'medium' | 'high' | 'critical')[] = ['low', 'medium', 'high', 'critical'];

    const user = mockUsers[Math.floor(Math.random() * mockUsers.length)];
    const channel = mockChannels[Math.floor(Math.random() * mockChannels.length)];
    const dataType = mockDataTypes[Math.floor(Math.random() * mockDataTypes.length)];
    const severity = mockSeverities[Math.floor(Math.random() * mockSeverities.length)];

    return {
      id: `VIO-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      policyId: 'PII_PROTECTION',
      policyName: 'PII Protection Policy',
      severity,
      status: 'detected',
      userId: `user_${Date.now()}`,
      userEmail: user.email,
      userName: user.name,
      department: user.dept,
      timestamp: new Date(),
      channel,
      dataTypes: [dataType],
      matchedContent: [
        {
          dataType,
          pattern: 'Sensitive data pattern',
          confidence: Math.floor(Math.random() * 30) + 70,
          context: `Detected ${dataType} in ${channel} transmission`,
          location: `${channel}_content`,
          count: Math.floor(Math.random() * 5) + 1
        }
      ],
      destination: channel === 'email' ? 'external@domain.com' : undefined,
      actionTaken: this.determineActions(severity, channel),
      falsePositive: false,
      riskScore: Math.floor(Math.random() * 40) + 60,
      evidence: []
    };
  }

  // Send DLP violation notification
  private async notifyDLPViolation(violation: DLPViolation): Promise<void> {
    const subject = `🚨 DLP VIOLATION DETECTED - ${violation.severity.toUpperCase()}`;
    const message = this.formatDLPNotification(violation);

    await emailService.sendEmail({
      to: 'vanursab71@gmail.com',
      subject,
      message,
      type: 'dlp'
    });
  }

  // Format DLP notification message
  private formatDLPNotification(violation: DLPViolation): string {
    return `
🚨 DATA LOSS PREVENTION ALERT 🚨
=================================

⚠️ UNAUTHORIZED DATA TRANSFER DETECTED ⚠️

🔍 VIOLATION DETAILS:
• Violation ID: ${violation.id}
• Policy: ${violation.policyName}
• Severity: ${violation.severity.toUpperCase()}
• Risk Score: ${violation.riskScore}/100

👤 USER INFORMATION:
• Name: ${violation.userName}
• Email: ${violation.userEmail}
• Department: ${violation.department}
• User ID: ${violation.userId}

📊 DATA DETAILS:
• Channel: ${violation.channel.toUpperCase()}
• Data Types: ${violation.dataTypes.join(', ')}
• Destination: ${violation.destination || 'N/A'}
• Detection Time: ${violation.timestamp.toLocaleString()}

🔍 DETECTED CONTENT:
${violation.matchedContent.map(match => 
  `• ${match.dataType}: ${match.pattern} (${match.confidence}% confidence)`
).join('\n')}

⚡ ACTIONS TAKEN:
${violation.actionTaken.map(action => `• ${action.replace('_', ' ').toUpperCase()}`).join('\n')}

🎯 IMMEDIATE ACTIONS REQUIRED:
1. 🔍 Review violation details in DLP dashboard
2. 👤 Contact user to verify business justification
3. 🚨 Investigate potential data breach
4. 📋 Document findings and resolution
5. 🛡️ Update DLP policies if necessary

🌐 ACCESS DLP DASHBOARD:
https://agentphantom.ai/data-loss-prevention

📧 This is an automated DLP alert from AgentPhantom.AI
🔒 Confidential - For authorized personnel only

---
AgentPhantom.AI Data Loss Prevention System
🛡️ Protecting sensitive data 24/7
📧 Contact: vanursab71@gmail.com
    `;
  }

  // Data discovery and classification
  public async discoverSensitiveData(paths: string[]): Promise<{
    totalFiles: number;
    sensitiveFiles: number;
    dataTypes: Map<string, number>;
    riskDistribution: Map<string, number>;
  }> {
    // Simulate data discovery process
    await new Promise(resolve => setTimeout(resolve, 2000));

    const results = {
      totalFiles: Math.floor(Math.random() * 10000) + 5000,
      sensitiveFiles: 0,
      dataTypes: new Map<string, number>(),
      riskDistribution: new Map<string, number>()
    };

    // Simulate finding sensitive data
    this.dataClassifications.forEach((classification, id) => {
      const count = Math.floor(Math.random() * 500) + 50;
      results.dataTypes.set(classification.name, count);
      results.sensitiveFiles += count;
    });

    // Risk distribution
    results.riskDistribution.set('critical', Math.floor(results.sensitiveFiles * 0.1));
    results.riskDistribution.set('high', Math.floor(results.sensitiveFiles * 0.2));
    results.riskDistribution.set('medium', Math.floor(results.sensitiveFiles * 0.4));
    results.riskDistribution.set('low', results.sensitiveFiles - 
      (results.riskDistribution.get('critical')! + 
       results.riskDistribution.get('high')! + 
       results.riskDistribution.get('medium')!));

    return results;
  }

  // Encryption recommendation engine
  public recommendEncryption(dataType: string, sensitivity: string, location: string): {
    required: boolean;
    algorithm: string;
    keyManagement: string;
    justification: string;
  } {
    let required = false;
    let algorithm = 'AES-256';
    let keyManagement = 'automatic';
    let justification = '';

    // Determine encryption requirements
    if (sensitivity === 'restricted' || dataType.includes('SSN') || dataType.includes('Credit Card')) {
      required = true;
      algorithm = 'AES-256';
      keyManagement = 'hsm';
      justification = 'High-sensitivity data requires strong encryption and HSM key management';
    } else if (sensitivity === 'confidential' || dataType.includes('Financial') || dataType.includes('Medical')) {
      required = true;
      algorithm = 'AES-256';
      keyManagement = 'manual';
      justification = 'Confidential data requires encryption with manual key management';
    } else if (sensitivity === 'internal') {
      required = location.includes('cloud') || location.includes('external');
      algorithm = 'AES-128';
      keyManagement = 'automatic';
      justification = required ? 'Internal data requires encryption when stored externally' : 'Encryption recommended but not required';
    }

    return { required, algorithm, keyManagement, justification };
  }

  // Access control recommendation
  public recommendAccessControls(dataType: string, sensitivity: string): {
    mfaRequired: boolean;
    roleBasedAccess: boolean;
    auditLevel: string;
    restrictions: string[];
  } {
    const recommendations = {
      mfaRequired: false,
      roleBasedAccess: true,
      auditLevel: 'basic',
      restrictions: [] as string[]
    };

    if (sensitivity === 'restricted') {
      recommendations.mfaRequired = true;
      recommendations.auditLevel = 'full';
      recommendations.restrictions.push('time_based_access', 'location_restrictions', 'device_restrictions');
    } else if (sensitivity === 'confidential') {
      recommendations.mfaRequired = true;
      recommendations.auditLevel = 'detailed';
      recommendations.restrictions.push('role_based_only', 'audit_all_access');
    } else if (sensitivity === 'internal') {
      recommendations.auditLevel = 'basic';
      recommendations.restrictions.push('internal_network_only');
    }

    return recommendations;
  }

  // Get violation statistics
  public getViolationStatistics(timeframe: 'day' | 'week' | 'month' = 'week'): {
    total: number;
    byChannel: Map<string, number>;
    byDataType: Map<string, number>;
    bySeverity: Map<string, number>;
    trend: number;
  } {
    const now = new Date();
    const timeframeDays = timeframe === 'day' ? 1 : timeframe === 'week' ? 7 : 30;
    const cutoff = new Date(now.getTime() - timeframeDays * 24 * 60 * 60 * 1000);

    const recentViolations = this.violationHistory.filter(v => v.timestamp >= cutoff);
    
    const stats = {
      total: recentViolations.length,
      byChannel: new Map<string, number>(),
      byDataType: new Map<string, number>(),
      bySeverity: new Map<string, number>(),
      trend: 0
    };

    // Aggregate statistics
    recentViolations.forEach(violation => {
      // By channel
      const channelCount = stats.byChannel.get(violation.channel) || 0;
      stats.byChannel.set(violation.channel, channelCount + 1);

      // By data type
      violation.dataTypes.forEach(dataType => {
        const typeCount = stats.byDataType.get(dataType) || 0;
        stats.byDataType.set(dataType, typeCount + 1);
      });

      // By severity
      const severityCount = stats.bySeverity.get(violation.severity) || 0;
      stats.bySeverity.set(violation.severity, severityCount + 1);
    });

    // Calculate trend (mock calculation)
    const previousPeriodViolations = this.violationHistory.filter(v => 
      v.timestamp >= new Date(cutoff.getTime() - timeframeDays * 24 * 60 * 60 * 1000) &&
      v.timestamp < cutoff
    );

    if (previousPeriodViolations.length > 0) {
      stats.trend = ((recentViolations.length - previousPeriodViolations.length) / previousPeriodViolations.length) * 100;
    }

    return stats;
  }
}

// Export singleton instance
export const dlpEngine = DLPEngine.getInstance();