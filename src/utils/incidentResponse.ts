import { Incident, Alert, Playbook, ContainmentAction, TimelineEntry, PlaybookExecution, PlaybookStepResult } from '../types';
import { emailService } from './emailService';

export class IncidentResponseEngine {
  private static instance: IncidentResponseEngine;

  public static getInstance(): IncidentResponseEngine {
    if (!IncidentResponseEngine.instance) {
      IncidentResponseEngine.instance = new IncidentResponseEngine();
    }
    return IncidentResponseEngine.instance;
  }

  // Auto-triage and prioritization
  public triageAlert(alert: Alert): {
    severity: 'low' | 'medium' | 'high' | 'critical';
    priority: number;
    assignedTeam: string;
    escalationRequired: boolean;
  } {
    let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';
    let priority = 5;
    let assignedTeam = 'SOC Level 1';
    let escalationRequired = false;

    // Priority scoring based on alert characteristics
    if (alert.priority === 'critical') {
      severity = 'critical';
      priority = 1;
      assignedTeam = 'SOC Level 3';
      escalationRequired = true;
    } else if (alert.priority === 'high') {
      severity = 'high';
      priority = 2;
      assignedTeam = 'SOC Level 2';
    } else if (alert.priority === 'medium') {
      severity = 'medium';
      priority = 3;
      assignedTeam = 'SOC Level 2';
    }

    // Additional scoring based on alert content
    if (alert.message.toLowerCase().includes('malware') || 
        alert.message.toLowerCase().includes('ransomware')) {
      severity = 'critical';
      priority = 1;
      escalationRequired = true;
    }

    if (alert.message.toLowerCase().includes('data breach') ||
        alert.message.toLowerCase().includes('exfiltration')) {
      severity = 'critical';
      priority = 1;
      assignedTeam = 'Incident Response Team';
      escalationRequired = true;
    }

    return { severity, priority, assignedTeam, escalationRequired };
  }

  // Create incident from alert
  public createIncidentFromAlert(alert: Alert): Incident {
    const triage = this.triageAlert(alert);
    
    const incident: Incident = {
      id: `INC-${Date.now().toString().slice(-6)}`,
      title: this.generateIncidentTitle(alert),
      description: alert.message,
      severity: triage.severity,
      status: 'new',
      priority: triage.priority,
      assignedTo: triage.assignedTeam,
      createdAt: new Date(),
      updatedAt: new Date(),
      affectedSystems: this.identifyAffectedSystems(alert),
      containmentActions: [],
      timeline: [
        {
          timestamp: new Date(),
          action: 'Incident created from alert',
          user: 'Auto-Triage System',
          details: `Alert ${alert.id} automatically converted to incident`,
          type: 'automated'
        }
      ],
      evidence: [
        {
          type: 'url_analysis',
          description: `Original alert: ${alert.message}`,
          path: `/alerts/${alert.id}`,
          collectedAt: new Date()
        }
      ],
      relatedAlertId: alert.id
    };

    // Auto-escalate if required
    if (triage.escalationRequired) {
      this.escalateIncident(incident);
    }

    return incident;
  }

  // Automated containment actions
  public async executeContainmentAction(action: ContainmentAction): Promise<{
    success: boolean;
    message: string;
    details?: any;
  }> {
    console.log(`Executing containment action: ${action.type} on ${action.target}`);
    
    // Simulate containment action execution
    await new Promise(resolve => setTimeout(resolve, 2000));

    switch (action.type) {
      case 'isolate_endpoint':
        return this.isolateEndpoint(action.target);
      
      case 'block_ip':
        return this.blockIP(action.target);
      
      case 'block_domain':
        return this.blockDomain(action.target);
      
      case 'quarantine_emails':
        return this.quarantineEmails(action.target);
      
      case 'disable_account':
        return this.disableAccount(action.target);
      
      case 'patch_system':
        return this.patchSystem(action.target);
      
      default:
        return {
          success: false,
          message: `Unknown containment action type: ${action.type}`
        };
    }
  }

  // Execute SOAR playbook
  public async executePlaybook(incident: Incident, playbook: Playbook): Promise<{
    success: boolean;
    executionId: string;
    containmentActions: ContainmentAction[];
    timelineEntries: TimelineEntry[];
    stepResults: PlaybookStepResult[];
  }> {
    const executionId = `EXEC-${Date.now()}`;
    const containmentActions: ContainmentAction[] = [];
    const timelineEntries: TimelineEntry[] = [];
    const stepResults: PlaybookStepResult[] = [];

    console.log(`Executing playbook ${playbook.name} for incident ${incident.id}`);

    // Add timeline entry for playbook start
    timelineEntries.push({
      timestamp: new Date(),
      action: `Playbook execution started: ${playbook.name}`,
      user: 'SOAR Engine',
      details: `Automated playbook execution initiated`,
      type: 'automated'
    });

    // Execute each step
    for (const step of playbook.steps) {
      const stepResult: PlaybookStepResult = {
        stepId: step.id,
        status: 'running',
        startedAt: new Date()
      };

      try {
        if (step.automated) {
          // Execute automated step
          const result = await this.executePlaybookStep(step, incident);
          
          stepResult.status = 'completed';
          stepResult.completedAt = new Date();
          stepResult.output = result;

          // Generate containment actions if applicable
          if (step.type === 'containment') {
            const action = this.generateContainmentAction(step, incident);
            if (action) {
              containmentActions.push(action);
            }
          }

          timelineEntries.push({
            timestamp: new Date(),
            action: `Automated step completed: ${step.name}`,
            user: 'SOAR Engine',
            details: `Step executed successfully: ${step.description}`,
            type: 'automated'
          });
        } else {
          // Manual step - mark as pending
          stepResult.status = 'pending';
          
          timelineEntries.push({
            timestamp: new Date(),
            action: `Manual step queued: ${step.name}`,
            user: 'SOAR Engine',
            details: `Manual intervention required: ${step.description}`,
            type: 'automated'
          });
        }
      } catch (error) {
        stepResult.status = 'failed';
        stepResult.completedAt = new Date();
        stepResult.error = error instanceof Error ? error.message : 'Unknown error';

        timelineEntries.push({
          timestamp: new Date(),
          action: `Step failed: ${step.name}`,
          user: 'SOAR Engine',
          details: `Error: ${stepResult.error}`,
          type: 'automated'
        });
      }

      stepResults.push(stepResult);
    }

    // Send notification about playbook execution
    await this.notifyPlaybookExecution(incident, playbook, stepResults);

    return {
      success: stepResults.every(r => r.status === 'completed' || r.status === 'pending'),
      executionId,
      containmentActions,
      timelineEntries,
      stepResults
    };
  }

  // Generate incident report
  public generateIncidentReport(incident: Incident): string {
    const report = `
INCIDENT RESPONSE REPORT
========================

Incident ID: ${incident.id}
Title: ${incident.title}
Severity: ${incident.severity.toUpperCase()}
Status: ${incident.status.toUpperCase()}
Priority: ${incident.priority}

INCIDENT DETAILS
================
Description: ${incident.description}
Created: ${incident.createdAt.toLocaleString()}
Last Updated: ${incident.updatedAt.toLocaleString()}
Assigned To: ${incident.assignedTo}

AFFECTED SYSTEMS
================
${incident.affectedSystems.map(system => `• ${system}`).join('\n')}

CONTAINMENT ACTIONS
===================
${incident.containmentActions.map(action => 
  `• ${action.type.replace('_', ' ').toUpperCase()}: ${action.target} (${action.status})`
).join('\n')}

TIMELINE
========
${incident.timeline.map(entry => 
  `${entry.timestamp.toLocaleString()} - ${entry.action} (${entry.user})\n  ${entry.details}`
).join('\n\n')}

EVIDENCE
========
${incident.evidence.map(evidence => 
  `• ${evidence.type.replace('_', ' ').toUpperCase()}: ${evidence.description}\n  Path: ${evidence.path}`
).join('\n\n')}

RECOMMENDATIONS
===============
${this.generateRecommendations(incident)}

LESSONS LEARNED
===============
${this.generateLessonsLearned(incident)}

Report Generated: ${new Date().toLocaleString()}
Generated by: AgentPhantom.AI Incident Response System
    `;

    return report;
  }

  // Private helper methods
  private generateIncidentTitle(alert: Alert): string {
    if (alert.type === 'ThreatScan') {
      if (alert.message.includes('phishing')) {
        return 'Phishing Attack Detected';
      } else if (alert.message.includes('malware')) {
        return 'Malware Infection Detected';
      } else if (alert.message.includes('suspicious')) {
        return 'Suspicious Activity Detected';
      }
      return 'Security Threat Detected';
    } else {
      return 'Security Issue Reported';
    }
  }

  private identifyAffectedSystems(alert: Alert): string[] {
    // Mock system identification based on alert content
    const systems: string[] = [];
    
    if (alert.message.includes('endpoint') || alert.message.includes('workstation')) {
      systems.push('user-workstation-01');
    }
    
    if (alert.message.includes('server') || alert.message.includes('database')) {
      systems.push('web-server-01', 'database-01');
    }
    
    if (alert.message.includes('network') || alert.message.includes('firewall')) {
      systems.push('firewall-01', 'network-switch-01');
    }
    
    return systems.length > 0 ? systems : ['unknown-system'];
  }

  private escalateIncident(incident: Incident): void {
    // Send escalation notification
    emailService.sendEmail({
      to: 'vanursab71@gmail.com',
      subject: `🚨 CRITICAL INCIDENT ESCALATION - ${incident.id}`,
      message: `
CRITICAL INCIDENT REQUIRES IMMEDIATE ATTENTION

Incident: ${incident.id}
Title: ${incident.title}
Severity: ${incident.severity.toUpperCase()}
Priority: ${incident.priority}

Description: ${incident.description}

Affected Systems: ${incident.affectedSystems.join(', ')}

This incident has been automatically escalated due to its critical nature.
Immediate response required.

Access Incident: https://agentphantom.ai/incident-response
      `,
      type: 'alert'
    });
  }

  private async isolateEndpoint(target: string): Promise<{ success: boolean; message: string; details?: any }> {
    // Mock endpoint isolation
    console.log(`Isolating endpoint: ${target}`);
    
    return {
      success: true,
      message: `Endpoint ${target} successfully isolated from network`,
      details: {
        action: 'Network isolation',
        method: 'Firewall rule update',
        timestamp: new Date(),
        reversible: true
      }
    };
  }

  private async blockIP(target: string): Promise<{ success: boolean; message: string; details?: any }> {
    // Mock IP blocking
    console.log(`Blocking IP: ${target}`);
    
    return {
      success: true,
      message: `IP address ${target} successfully blocked`,
      details: {
        action: 'IP blocking',
        method: 'Firewall rule addition',
        timestamp: new Date(),
        scope: 'Global'
      }
    };
  }

  private async blockDomain(target: string): Promise<{ success: boolean; message: string; details?: any }> {
    // Mock domain blocking
    console.log(`Blocking domain: ${target}`);
    
    return {
      success: true,
      message: `Domain ${target} successfully blocked`,
      details: {
        action: 'DNS blocking',
        method: 'DNS sinkhole',
        timestamp: new Date(),
        scope: 'Organization-wide'
      }
    };
  }

  private async quarantineEmails(target: string): Promise<{ success: boolean; message: string; details?: any }> {
    // Mock email quarantine
    console.log(`Quarantining emails for: ${target}`);
    
    return {
      success: true,
      message: `Emails quarantined for ${target}`,
      details: {
        action: 'Email quarantine',
        method: 'Exchange rule',
        timestamp: new Date(),
        count: Math.floor(Math.random() * 50) + 10
      }
    };
  }

  private async disableAccount(target: string): Promise<{ success: boolean; message: string; details?: any }> {
    // Mock account disabling
    console.log(`Disabling account: ${target}`);
    
    return {
      success: true,
      message: `Account ${target} successfully disabled`,
      details: {
        action: 'Account disable',
        method: 'Active Directory',
        timestamp: new Date(),
        reversible: true
      }
    };
  }

  private async patchSystem(target: string): Promise<{ success: boolean; message: string; details?: any }> {
    // Mock system patching
    console.log(`Patching system: ${target}`);
    
    return {
      success: true,
      message: `System ${target} patching initiated`,
      details: {
        action: 'Security patching',
        method: 'WSUS deployment',
        timestamp: new Date(),
        estimatedCompletion: new Date(Date.now() + 3600000)
      }
    };
  }

  private async executePlaybookStep(step: any, incident: Incident): Promise<any> {
    // Mock step execution
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    switch (step.type) {
      case 'containment':
        return { action: 'containment_executed', target: incident.affectedSystems[0] };
      case 'investigation':
        return { action: 'evidence_collected', items: 3 };
      case 'analysis':
        return { action: 'analysis_completed', findings: 'Malware signatures detected' };
      case 'communication':
        return { action: 'notification_sent', recipients: 5 };
      default:
        return { action: 'step_completed' };
    }
  }

  private generateContainmentAction(step: any, incident: Incident): ContainmentAction | null {
    if (step.type !== 'containment') return null;
    
    return {
      id: `CA-${Date.now()}`,
      type: 'isolate_endpoint',
      target: incident.affectedSystems[0] || 'unknown',
      status: 'completed',
      timestamp: new Date(),
      details: `Automated containment from playbook step: ${step.name}`,
      automatedBy: 'SOAR Engine'
    };
  }

  private async notifyPlaybookExecution(incident: Incident, playbook: Playbook, results: PlaybookStepResult[]): Promise<void> {
    const successfulSteps = results.filter(r => r.status === 'completed').length;
    const totalSteps = results.length;
    
    await emailService.sendEmail({
      to: 'vanursab71@gmail.com',
      subject: `🤖 SOAR Playbook Execution Complete - ${incident.id}`,
      message: `
SOAR PLAYBOOK EXECUTION REPORT

Incident: ${incident.id} - ${incident.title}
Playbook: ${playbook.name}
Execution Status: ${successfulSteps}/${totalSteps} steps completed

Automated Actions Taken:
${results.filter(r => r.status === 'completed').map(r => 
  `• Step ${r.stepId}: Completed successfully`
).join('\n')}

Manual Actions Required:
${results.filter(r => r.status === 'pending').map(r => 
  `• Step ${r.stepId}: Requires manual intervention`
).join('\n')}

Failed Actions:
${results.filter(r => r.status === 'failed').map(r => 
  `• Step ${r.stepId}: Failed - ${r.error}`
).join('\n')}

Next Steps:
- Review manual action items
- Verify automated containment effectiveness
- Continue incident investigation

Access Incident: https://agentphantom.ai/incident-response
      `,
      type: 'alert'
    });
  }

  private generateRecommendations(incident: Incident): string {
    const recommendations = [];
    
    if (incident.severity === 'critical') {
      recommendations.push('• Conduct thorough forensic analysis');
      recommendations.push('• Review and update incident response procedures');
      recommendations.push('• Consider external forensic assistance');
    }
    
    if (incident.title.includes('Phishing')) {
      recommendations.push('• Enhance email security training');
      recommendations.push('• Implement additional email filtering');
      recommendations.push('• Review email security policies');
    }
    
    if (incident.title.includes('Malware')) {
      recommendations.push('• Update antivirus signatures');
      recommendations.push('• Review endpoint protection policies');
      recommendations.push('• Conduct vulnerability assessment');
    }
    
    recommendations.push('• Update threat intelligence feeds');
    recommendations.push('• Review security monitoring rules');
    recommendations.push('• Document lessons learned');
    
    return recommendations.join('\n');
  }

  private generateLessonsLearned(incident: Incident): string {
    const lessons = [];
    
    lessons.push('• Automated containment reduced response time significantly');
    lessons.push('• Early detection prevented widespread impact');
    lessons.push('• Cross-team coordination was effective');
    
    if (incident.containmentActions.length > 0) {
      lessons.push('• Containment actions were successful in limiting damage');
    }
    
    lessons.push('• Regular security awareness training is crucial');
    lessons.push('• Incident response playbooks proved valuable');
    
    return lessons.join('\n');
  }
}

// Export singleton instance
export const incidentResponseEngine = IncidentResponseEngine.getInstance();