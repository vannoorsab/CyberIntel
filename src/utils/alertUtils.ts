import { Alert } from '../types';
import { emailService } from './emailService';

export const createThreatAlert = (
  userEmail: string,
  target: string,
  riskLevel: string,
  scanId: string
): Omit<Alert, 'id' | 'timestamp'> => {
  const priority = riskLevel === 'dangerous' ? 'critical' : 'high';
  
  let message = '';
  if (riskLevel === 'dangerous') {
    if (target.includes('http')) {
      message = `🔴 High-risk URL detected: ${target.length > 50 ? target.substring(0, 50) + '...' : target}`;
    } else {
      message = `🔴 Malicious file detected: ${target}`;
    }
    
    // Send email alert for dangerous threats
    emailService.sendThreatAlert(userEmail, target, riskLevel);
  } else {
    message = `⚠️ Suspicious activity detected from ${userEmail}`;
  }

  return {
    type: 'ThreatScan',
    userEmail,
    message,
    status: 'unread',
    relatedId: scanId,
    priority
  };
};

export const createBugAlert = (
  userEmail: string,
  bugTitle: string,
  bugId: string
): Omit<Alert, 'id' | 'timestamp'> => {
  // Send email alert for bug reports
  emailService.sendBugReportAlert(userEmail, bugTitle, 'User reported a security issue that requires investigation.');

  return {
    type: 'BugReport',
    userEmail,
    message: `🛠️ New security bug reported: "${bugTitle.length > 60 ? bugTitle.substring(0, 60) + '...' : bugTitle}"`,
    status: 'unread',
    relatedId: bugId,
    priority: 'medium'
  };
};

export const createDLPAlert = (
  userEmail: string,
  policyName: string,
  violationId: string,
  severity: 'low' | 'medium' | 'high' | 'critical'
): Omit<Alert, 'id' | 'timestamp'> => {
  const priority = severity === 'critical' ? 'critical' : 
                  severity === 'high' ? 'high' : 
                  severity === 'medium' ? 'medium' : 'low';

  // Send email alert for high-risk DLP violations
  if (severity === 'critical' || severity === 'high') {
    emailService.sendEmail({
      to: 'vanursab71@gmail.com',
      subject: `🚨 DLP VIOLATION - ${severity.toUpperCase()}`,
      message: `
DLP VIOLATION DETECTED
======================

Policy: ${policyName}
User: ${userEmail}
Severity: ${severity.toUpperCase()}
Violation ID: ${violationId}

Immediate investigation required.
Access DLP Dashboard: https://cyberintel.ai/data-loss-prevention
      `,
      type: 'dlp'
    });
  }

  return {
    type: 'DLPViolation',
    userEmail,
    message: `🛡️ DLP violation: ${policyName} by ${userEmail}`,
    status: 'unread',
    relatedId: violationId,
    priority
  };
};

export const createForensicAlert = (
  userEmail: string,
  activity: string,
  activityId: string,
  riskScore: number
): Omit<Alert, 'id' | 'timestamp'> => {
  const priority = riskScore >= 90 ? 'critical' : 
                  riskScore >= 70 ? 'high' : 
                  riskScore >= 50 ? 'medium' : 'low';

  // Send email alert for high-risk forensic events
  if (riskScore >= 80) {
    emailService.sendEmail({
      to: 'vanursab71@gmail.com',
      subject: `🔍 HIGH-RISK FORENSIC ACTIVITY - Risk Score: ${riskScore}`,
      message: `
HIGH-RISK FORENSIC ACTIVITY DETECTED
====================================

Activity: ${activity}
User: ${userEmail}
Risk Score: ${riskScore}/100
Activity ID: ${activityId}

Immediate review required.
Access Forensics Dashboard: https://cyberintel.ai/forensics-audit
      `,
      type: 'forensic'
    });
  }

  return {
    type: 'ForensicEvent',
    userEmail,
    message: `🔍 High-risk forensic activity: ${activity} by ${userEmail}`,
    status: 'unread',
    relatedId: activityId,
    priority
  };
};

export const playAlertSound = (priority: string) => {
  // Enhanced alert sound function
  if ('AudioContext' in window || 'webkitAudioContext' in window) {
    try {
      const AudioContext = window.AudioContext || (window as any).webkitAudioContext;
      const audioContext = new AudioContext();
      
      if (priority === 'critical') {
        // Critical alert: Three beeps
        [0, 0.3, 0.6].forEach((delay) => {
          setTimeout(() => {
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            oscillator.frequency.setValueAtTime(800, audioContext.currentTime);
            oscillator.type = 'sine';
            
            gainNode.gain.setValueAtTime(0.15, audioContext.currentTime);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.2);
            
            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.2);
          }, delay * 1000);
        });
      } else {
        // Regular alert: Single beep
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        oscillator.frequency.setValueAtTime(600, audioContext.currentTime);
        oscillator.type = 'sine';
        
        gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.3);
        
        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 0.3);
      }
    } catch (error) {
      console.log('Audio notification not available');
    }
  }
};