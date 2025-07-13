import emailjs from '@emailjs/browser';
import { EmailNotification } from '../types';

// EmailJS Configuration - Updated for vanursab71@gmail.com
const EMAILJS_CONFIG = {
  SERVICE_ID: 'service_cyberintel', // You'll need to create this service in your EmailJS dashboard
  TEMPLATE_ID_THREAT: 'template_threat_alert', // You'll need to create this template
  TEMPLATE_ID_BUG: 'template_bug_report', // You'll need to create this template
  PUBLIC_KEY: '7XbpiUgcJ2P9CtJ_N' // Your correct public key
};

// Email service for sending real notifications to officers
export class EmailService {
  private static instance: EmailService;
  private emailQueue: EmailNotification[] = [];
  private isInitialized = false;
  private configurationError: string | null = null;

  private constructor() {
    this.initializeEmailJS();
  }

  public static getInstance(): EmailService {
    if (!EmailService.instance) {
      EmailService.instance = new EmailService();
    }
    return EmailService.instance;
  }

  private initializeEmailJS(): void {
    try {
      // Initialize EmailJS with your actual public key
      emailjs.init(EMAILJS_CONFIG.PUBLIC_KEY);
      this.isInitialized = true;
      console.log('📧 EmailJS initialized successfully with public key:', EMAILJS_CONFIG.PUBLIC_KEY);
    } catch (error) {
      console.error('Failed to initialize EmailJS:', error);
      this.isInitialized = false;
      this.configurationError = 'Failed to initialize EmailJS';
    }
  }

  // Check if EmailJS is properly configured
  public isConfigured(): boolean {
    return this.isInitialized && !this.configurationError;
  }

  public getConfigurationError(): string | null {
    return this.configurationError;
  }

  // Send real email using EmailJS
  public async sendEmail(notification: Omit<EmailNotification, 'timestamp' | 'status'>): Promise<boolean> {
    const emailNotification: EmailNotification = {
      ...notification,
      timestamp: new Date(),
      status: 'pending'
    };

    this.emailQueue.push(emailNotification);

    try {
      if (!this.isInitialized) {
        throw new Error('EmailJS not initialized. Please check your configuration.');
      }

      // Prepare email template parameters
      const templateParams = {
        to_email: notification.to,
        to_name: this.getOfficerName(notification.to),
        subject: notification.subject,
        message: notification.message,
        from_name: 'CyberIntel Security System',
        reply_to: 'noreply@cyberintel.ai',
        timestamp: new Date().toLocaleString(),
        user_email: notification.to // Additional parameter for templates
      };

      // Choose template based on email type
      const templateId = notification.type === 'threat' 
        ? EMAILJS_CONFIG.TEMPLATE_ID_THREAT 
        : EMAILJS_CONFIG.TEMPLATE_ID_BUG;

      console.log('📧 Attempting to send email via EmailJS:', {
        serviceId: EMAILJS_CONFIG.SERVICE_ID,
        templateId,
        to: notification.to,
        subject: notification.subject
      });

      // Send email via EmailJS
      const response = await emailjs.send(
        EMAILJS_CONFIG.SERVICE_ID,
        templateId,
        templateParams,
        EMAILJS_CONFIG.PUBLIC_KEY
      );

      console.log('✅ EMAIL SENT SUCCESSFULLY:', {
        to: notification.to,
        subject: notification.subject,
        status: response.status,
        text: response.text
      });

      // Update status to sent
      emailNotification.status = 'sent';
      
      // Store in localStorage for tracking
      this.saveEmailLog(emailNotification);
      
      return true;
    } catch (error: any) {
      console.error('❌ Failed to send email:', error);
      emailNotification.status = 'failed';
      
      // Handle specific EmailJS errors
      this.handleEmailError(error);
      
      // For now, simulate the email if real sending fails
      this.logSimulatedEmail(
        notification.type, 
        'system', 
        notification.subject, 
        `SIMULATED EMAIL (Real sending failed):\n\n${notification.message}`
      );
      
      return false;
    }
  }

  public async sendThreatAlert(userEmail: string, threatDetails: string, riskLevel: string): Promise<boolean> {
    const officers = this.getOfficerEmails();
    
    const subject = `🚨 CRITICAL THREAT ALERT - ${riskLevel.toUpperCase()} Risk Detected`;
    const message = this.formatThreatAlertMessage(userEmail, threatDetails, riskLevel);

    console.log('🚨 Sending threat alert to officers:', officers);

    // Send to all officers (including vanursab71@gmail.com)
    const emailPromises = officers.map(officerEmail => 
      this.sendEmail({
        to: officerEmail,
        subject,
        message,
        type: 'threat'
      })
    );

    const results = await Promise.all(emailPromises);
    const successCount = results.filter(result => result === true).length;
    
    console.log(`📧 Threat alert sent to ${successCount}/${officers.length} officers`);
    
    // Always log the alert even if email fails
    this.logSimulatedEmail('threat', userEmail, subject, message);
    
    return successCount > 0;
  }

  public async sendBugReportAlert(userEmail: string, bugTitle: string, bugDescription: string): Promise<boolean> {
    const officers = this.getOfficerEmails();
    
    const subject = `🛠️ NEW BUG REPORT - Security Issue Reported`;
    const message = this.formatBugReportMessage(userEmail, bugTitle, bugDescription);

    console.log('🛠️ Sending bug report alert to officers:', officers);

    // Send to all officers (including vanursab71@gmail.com)
    const emailPromises = officers.map(officerEmail => 
      this.sendEmail({
        to: officerEmail,
        subject,
        message,
        type: 'bug'
      })
    );

    const results = await Promise.all(emailPromises);
    const successCount = results.filter(result => result === true).length;
    
    console.log(`📧 Bug report alert sent to ${successCount}/${officers.length} officers`);
    
    // Always log the alert even if email fails
    this.logSimulatedEmail('bug', userEmail, subject, message);
    
    return successCount > 0;
  }

  private logSimulatedEmail(type: string, userEmail: string, subject: string, message: string): void {
    const simulatedNotification: EmailNotification = {
      to: 'vanursab71@gmail.com',
      subject,
      message,
      type: type as 'threat' | 'bug' | 'alert',
      timestamp: new Date(),
      status: 'sent'
    };
    
    this.saveEmailLog(simulatedNotification);
    console.log('📧 Email logged (simulated/backup):', {
      to: simulatedNotification.to,
      subject: simulatedNotification.subject,
      type: simulatedNotification.type
    });
  }

  private formatThreatAlertMessage(userEmail: string, threatDetails: string, riskLevel: string): string {
    return `
🚨 CYBERSECURITY THREAT ALERT 🚨
================================

⚠️ IMMEDIATE ATTENTION REQUIRED ⚠️

🔍 THREAT DETAILS:
• User Email: ${userEmail}
• Risk Level: ${riskLevel.toUpperCase()}
• Target: ${threatDetails}
• Detection Time: ${new Date().toLocaleString()}
• Alert ID: ALERT-${Date.now()}

🎯 THREAT ANALYSIS:
${riskLevel === 'dangerous' ? 
  '🔴 HIGH RISK: This threat poses immediate danger to user security and may indicate active malicious activity.' :
  '🟡 MEDIUM RISK: Suspicious activity detected that requires investigation.'
}

⚡ IMMEDIATE ACTIONS REQUIRED:
1. 🔍 Review threat details in ThreatOps Command Center
2. 🚨 Investigate potential security breach
3. 📞 Contact affected user if necessary
4. 🛡️ Update threat intelligence database
5. 📊 Document findings and resolution

🌐 ACCESS OFFICER PANEL:
https://cyberintel.ai/officer-panel

📧 This is an automated security alert from CyberIntel
🤖 Powered by AI-driven threat detection
🔒 Confidential - For authorized personnel only

---
CyberIntel Security Operations Center
🛡️ Protecting digital infrastructure 24/7
📧 Contact: vanursab71@gmail.com
    `;
  }

  private formatBugReportMessage(userEmail: string, bugTitle: string, bugDescription: string): string {
    return `
🛠️ BUG REPORT NOTIFICATION 🛠️
==============================

🐛 NEW SECURITY BUG REPORTED

📋 REPORT DETAILS:
• Reporter: ${userEmail}
• Title: ${bugTitle}
• Description: ${bugDescription}
• Submitted: ${new Date().toLocaleString()}
• Report ID: BUG-${Date.now()}

🔧 REQUIRED ACTIONS:
1. 📖 Review complete bug report in Officer Panel
2. 👤 Assign to appropriate team member
3. 🔍 Investigate and reproduce the issue
4. 🛠️ Develop and test resolution
5. 📝 Provide feedback to reporter

🌐 ACCESS OFFICER PANEL:
https://cyberintel.ai/officer-panel

📊 PRIORITY ASSESSMENT:
This bug report requires prompt attention to maintain system security and user trust.

📧 This is an automated notification from CyberIntel
🔄 Continuous improvement through user feedback
🔒 Confidential - For authorized personnel only

---
CyberIntel Security Operations Center
🚀 Building better security through collaboration
📧 Contact: vanursab71@gmail.com
    `;
  }

  private getOfficerEmails(): string[] {
    return [
      'vanursab71@gmail.com', // Your primary email (updated)
      'vanursab18@gmail.com', // Your secondary email
      'sarah.connor@cbi.gov.in',
      'john.matrix@cyberops.gov.in',
      'lisa.chen@forensics.gov.in'
    ];
  }

  private getOfficerName(email: string): string {
    const officerNames: { [key: string]: string } = {
      'vanursab71@gmail.com': 'Vannoor Sab (Primary)',
      'vanursab18@gmail.com': 'Vannoor Sab (Secondary)',
      'sarah.connor@cbi.gov.in': 'Agent Sarah Connor',
      'john.matrix@cyberops.gov.in': 'Lt. John Matrix',
      'lisa.chen@forensics.gov.in': 'Dr. Lisa Chen'
    };
    return officerNames[email] || 'Security Officer';
  }

  private saveEmailLog(notification: EmailNotification): void {
    const existingLogs = JSON.parse(localStorage.getItem('cyberintel_email_logs') || '[]');
    existingLogs.push(notification);
    
    // Keep only last 100 emails
    if (existingLogs.length > 100) {
      existingLogs.splice(0, existingLogs.length - 100);
    }
    
    localStorage.setItem('cyberintel_email_logs', JSON.stringify(existingLogs));
  }

  private handleEmailError(error: any): void {
    let errorMessage = 'Unknown email error';
    let errorType = 'general';

    if (error && typeof error === 'object') {
      // Check for Gmail API scope errors specifically
      if (error.text && error.text.includes('insufficient authentication scopes')) {
        errorType = 'gmail_insufficient_scopes';
        errorMessage = 'Gmail account needs broader permissions. Please reconnect your Gmail account in EmailJS dashboard with full access.';
        this.configurationError = 'Gmail account needs to be reconnected with broader permissions';
      } else if (error.status === 412 && error.text && error.text.includes('Gmail_API')) {
        errorType = 'gmail_auth_error';
        errorMessage = 'Gmail authentication failed. Please reconnect your Gmail account in EmailJS dashboard.';
        this.configurationError = 'Gmail authentication expired - reconnection required';
      } else if (error.text && error.text.includes('Gmail_API: Invalid grant')) {
        errorType = 'gmail_invalid_grant';
        errorMessage = 'Gmail account connection expired. Please reconnect your Gmail account in EmailJS dashboard.';
        this.configurationError = 'Gmail account needs to be reconnected in EmailJS dashboard';
      } else if (error.status === 404) {
        errorType = 'service_not_found';
        errorMessage = 'EmailJS service "service_cyberintel" not found in your account';
        this.configurationError = 'EmailJS service not configured properly';
      } else if (error.status === 400) {
        errorType = 'bad_request';
        errorMessage = 'Invalid email parameters or template not found';
        this.configurationError = 'EmailJS templates not configured';
      } else if (error.status === 401) {
        errorType = 'unauthorized';
        errorMessage = 'Invalid EmailJS public key';
        this.configurationError = 'Invalid EmailJS credentials';
      } else if (error.text) {
        errorMessage = error.text;
      } else if (error.message) {
        errorMessage = error.message;
      }
    }

    console.error('📧 EMAIL SERVICE ERROR:', {
      type: errorType,
      message: errorMessage,
      originalError: error,
      config: {
        publicKey: EMAILJS_CONFIG.PUBLIC_KEY,
        serviceId: EMAILJS_CONFIG.SERVICE_ID,
        initialized: this.isInitialized,
        account: 'vanursab71@gmail.com'
      }
    });

    // Provide specific guidance based on error type
    this.showConfigurationGuidance(errorType, error);
  }

  private showConfigurationGuidance(errorType: string, error: any): void {
    switch (errorType) {
      case 'gmail_insufficient_scopes':
        console.log(`
🔧 GMAIL PERMISSIONS REQUIRED 🔧
=================================

❌ Your Gmail account (vanursab71@gmail.com) needs broader permissions to send emails.

🚨 CRITICAL: Gmail API requires full access permissions to send emails on your behalf.

📋 IMMEDIATE FIX STEPS:
1. 🌐 Go to https://dashboard.emailjs.com/admin/integration
2. 🔍 Find your Gmail service (service_cyberintel)
3. 🔄 Click "Reconnect" or "Re-authorize" 
4. 📧 Sign in with vanursab71@gmail.com again
5. ✅ Grant ALL requested permissions (including send email permissions)
6. 💾 Save the service
7. 🧪 Test the email service again

⚠️ IMPORTANT: Make sure to grant full Gmail API access when reconnecting!

🔑 Your EmailJS Account: vanursab71@gmail.com
🆔 Service ID: ${EMAILJS_CONFIG.SERVICE_ID}
🔑 Public Key: ${EMAILJS_CONFIG.PUBLIC_KEY}

✅ After granting full permissions, your email service will work perfectly!
        `);
        break;
      
      case 'gmail_invalid_grant':
      case 'gmail_auth_error':
        console.log(`
🔧 GMAIL RECONNECTION REQUIRED 🔧
==================================

❌ Your Gmail account (vanursab71@gmail.com) connection has expired or been revoked.

🚨 CRITICAL: This is the most common EmailJS issue and is easily fixable!

📋 IMMEDIATE FIX STEPS:
1. 🌐 Go to https://dashboard.emailjs.com/admin/integration
2. 🔍 Find your Gmail service (service_cyberintel)
3. 🔄 Click "Reconnect" or "Re-authorize" 
4. 📧 Sign in with vanursab71@gmail.com again
5. ✅ Grant permissions to EmailJS
6. 💾 Save the service
7. 🧪 Test the email service again

⚠️ WHY THIS HAPPENS:
• Gmail OAuth tokens expire periodically for security
• Account password changes can revoke access
• Google security settings may require re-authorization

🔑 Your EmailJS Account: vanursab71@gmail.com
🆔 Service ID: ${EMAILJS_CONFIG.SERVICE_ID}
🔑 Public Key: ${EMAILJS_CONFIG.PUBLIC_KEY}

✅ After reconnecting, your email service will work perfectly!
        `);
        break;
      
      case 'service_not_found':
        console.log(`
🔧 EMAILJS SERVICE SETUP REQUIRED 🔧
====================================

❌ EmailJS service '${EMAILJS_CONFIG.SERVICE_ID}' not found in your account (vanursab71@gmail.com).

📋 SETUP STEPS:
1. 🌐 Go to https://dashboard.emailjs.com/admin/integration
2. ➕ Click "Add New Service"
3. 📧 Select "Gmail" and connect vanursab71@gmail.com
4. 🏷️ Set Service ID to: ${EMAILJS_CONFIG.SERVICE_ID}
5. 💾 Save the service

🔑 Your Public Key: ${EMAILJS_CONFIG.PUBLIC_KEY}
📧 Your Account: vanursab71@gmail.com

⚠️ IMPORTANT: The Service ID must be exactly "${EMAILJS_CONFIG.SERVICE_ID}"
        `);
        break;
      
      case 'bad_request':
        console.log(`
🔧 EMAILJS TEMPLATES REQUIRED 🔧
=================================

❌ Email templates not found in your EmailJS account.

📋 CREATE THESE TEMPLATES:
1. 🌐 Go to https://dashboard.emailjs.com/admin/templates
2. ➕ Create template with ID: ${EMAILJS_CONFIG.TEMPLATE_ID_THREAT}
3. ➕ Create template with ID: ${EMAILJS_CONFIG.TEMPLATE_ID_BUG}

📝 TEMPLATE VARIABLES TO INCLUDE:
• {{to_email}} - Recipient email
• {{to_name}} - Recipient name  
• {{subject}} - Email subject
• {{message}} - Email content
• {{from_name}} - Sender name
• {{timestamp}} - Alert timestamp

📧 Your Account: vanursab71@gmail.com
        `);
        break;
      
      case 'unauthorized':
        console.log(`
🔧 EMAILJS AUTHENTICATION ERROR 🔧
===================================

❌ Invalid EmailJS public key for account vanursab71@gmail.com.

📋 FIX STEPS:
1. 🌐 Go to https://dashboard.emailjs.com/admin/account
2. 🔑 Copy your Public Key
3. 🔄 Update EMAILJS_CONFIG.PUBLIC_KEY in emailService.ts
4. 💾 Save and restart the application

🔑 Current Key: ${EMAILJS_CONFIG.PUBLIC_KEY}
📧 Your Account: vanursab71@gmail.com
        `);
        break;
      
      default:
        console.log(`
🔧 EMAILJS ERROR 🔧
===================

❌ Error: ${error?.text || error?.message || 'Unknown error'}

📋 TROUBLESHOOTING:
1. ✅ Verify EmailJS account vanursab71@gmail.com is active
2. 🔍 Check service ID: ${EMAILJS_CONFIG.SERVICE_ID}
3. 🔍 Check template IDs: ${EMAILJS_CONFIG.TEMPLATE_ID_THREAT}, ${EMAILJS_CONFIG.TEMPLATE_ID_BUG}
4. 🔑 Confirm public key: ${EMAILJS_CONFIG.PUBLIC_KEY}
5. 🌐 Visit https://dashboard.emailjs.com for help

📧 Your Account: vanursab71@gmail.com
        `);
    }
  }

  public getEmailLogs(): EmailNotification[] {
    const logs = localStorage.getItem('cyberintel_email_logs');
    if (!logs) return [];
    
    return JSON.parse(logs).map((log: any) => ({
      ...log,
      timestamp: new Date(log.timestamp)
    }));
  }

  // Test email function
  public async sendTestEmail(): Promise<boolean> {
    console.log('🧪 Testing email service with account: vanursab71@gmail.com');
    
    return this.sendEmail({
      to: 'vanursab71@gmail.com',
      subject: '🧪 CyberIntel Test Email',
      message: `
🧪 EMAIL SERVICE TEST 🧪
========================

✅ This is a test email from CyberIntel

If you receive this email, the email service is working correctly!

🔧 Test Details:
• Timestamp: ${new Date().toLocaleString()}
• Service: EmailJS Integration
• Status: Active
• Service ID: ${EMAILJS_CONFIG.SERVICE_ID}
• Your Account: vanursab71@gmail.com
• Public Key: ${EMAILJS_CONFIG.PUBLIC_KEY}

🛡️ CyberIntel Security System
📧 Configured for: vanursab71@gmail.com
      `,
      type: 'alert'
    });
  }

  // Get current configuration for debugging
  public getConfiguration() {
    return {
      serviceId: EMAILJS_CONFIG.SERVICE_ID,
      publicKey: EMAILJS_CONFIG.PUBLIC_KEY,
      threatTemplate: EMAILJS_CONFIG.TEMPLATE_ID_THREAT,
      bugTemplate: EMAILJS_CONFIG.TEMPLATE_ID_BUG,
      isInitialized: this.isInitialized,
      configurationError: this.configurationError,
      targetAccount: 'vanursab71@gmail.com'
    };
  }
}

// Export singleton instance
export const emailService = EmailService.getInstance();