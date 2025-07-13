import { ScanResult, BugReport } from '../types';

const analyzeURLSecurity = (url: string): { riskLevel: 'safe' | 'suspicious' | 'dangerous', analysis: any } => {
  const urlObj = new URL(url);
  const domain = urlObj.hostname.toLowerCase();
  const path = urlObj.pathname.toLowerCase();
  const protocol = urlObj.protocol;
  
  // Check for suspicious path patterns
  const suspiciousPatterns = [
    '/login', '/verify', '/confirm', '/update', '/secure', '/account',
    '/banking', '/paypal', '/amazon', '/microsoft', '/google', '/apple',
    '/suspended', '/locked', '/expired', '/urgent', '/immediate',
    '/evil', '/phish', '/scam', '/fake', '/malware', '/virus'
  ];
  
  const hasSuspiciousPath = suspiciousPatterns.some(pattern => path.includes(pattern));
  
  // Check for suspicious domains
  const suspiciousDomains = [
    'bit.ly', 'tinyurl.com', 'short.link', 'suspicious-site.net',
    'example-phishing.com', 'fake-bank.com', 'phishing-test.org'
  ];
  
  const isSuspiciousDomain = suspiciousDomains.some(suspDomain => domain.includes(suspDomain));
  
  // Check for legitimate domains with suspicious paths
  const legitimateDomains = [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com',
    'facebook.com', 'twitter.com', 'linkedin.com', 'github.com', 'example.com'
  ];
  
  const isLegitimateBase = legitimateDomains.some(legit => domain.includes(legit));
  
  let riskLevel: 'safe' | 'suspicious' | 'dangerous';
  let analysis = {
    protocol,
    domain,
    path,
    hasSSL: protocol === 'https:',
    hasSuspiciousPath,
    isSuspiciousDomain,
    isLegitimateBase,
    domainAge: 'Unknown',
    reputation: 'Unknown'
  };
  
  // Risk assessment logic
  if (isSuspiciousDomain || (isLegitimateBase && hasSuspiciousPath)) {
    riskLevel = 'dangerous';
    analysis.reputation = 'Flagged as malicious';
  } else if (hasSuspiciousPath || !analysis.hasSSL || domain.length > 50) {
    riskLevel = 'suspicious';
    analysis.reputation = 'Limited or concerning';
  } else {
    riskLevel = 'safe';
    analysis.reputation = 'Good standing';
  }
  
  return { riskLevel, analysis };
};

const analyzeQRCodeSecurity = (qrContent: string): { riskLevel: 'safe' | 'suspicious' | 'dangerous', analysis: any } => {
  // Mock QR code content analysis
  const content = qrContent.toLowerCase();
  
  // Check for URL patterns
  const isURL = content.startsWith('http://') || content.startsWith('https://') || content.includes('www.');
  
  // Check for suspicious QR code patterns
  const suspiciousPatterns = [
    'bit.ly', 'tinyurl', 'short.link', 'qr-phish', 'fake-qr',
    'malicious-qr', 'phishing', 'scam', 'virus', 'malware',
    'urgent', 'winner', 'prize', 'claim', 'verify-account',
    'suspended', 'locked', 'expired', 'bitcoin', 'crypto-wallet'
  ];
  
  const hasSuspiciousContent = suspiciousPatterns.some(pattern => content.includes(pattern));
  
  // Check for legitimate services
  const legitimateServices = [
    'google.com', 'apple.com', 'microsoft.com', 'amazon.com',
    'paypal.com', 'facebook.com', 'instagram.com', 'twitter.com',
    'linkedin.com', 'youtube.com', 'github.com', 'spotify.com'
  ];
  
  const isLegitimateService = legitimateServices.some(service => content.includes(service));
  
  // Check for WiFi credentials (WIFI:T:WPA;S:NetworkName;P:Password;;)
  const isWiFiQR = content.startsWith('wifi:') || content.includes('wifi:t:');
  
  // Check for contact info (vCard format)
  const isContactQR = content.startsWith('begin:vcard') || content.includes('vcard');
  
  // Check for SMS/Phone patterns
  const isSMSQR = content.startsWith('sms:') || content.startsWith('tel:');
  
  // Check for email patterns
  const isEmailQR = content.startsWith('mailto:');
  
  let riskLevel: 'safe' | 'suspicious' | 'dangerous';
  let analysis = {
    content: qrContent,
    contentType: 'unknown',
    isURL,
    isWiFiQR,
    isContactQR,
    isSMSQR,
    isEmailQR,
    hasSuspiciousContent,
    isLegitimateService,
    hasEncryption: content.includes('https://'),
    reputation: 'Unknown'
  };
  
  // Determine content type
  if (isURL) analysis.contentType = 'URL';
  else if (isWiFiQR) analysis.contentType = 'WiFi Credentials';
  else if (isContactQR) analysis.contentType = 'Contact Information';
  else if (isSMSQR) analysis.contentType = 'SMS/Phone';
  else if (isEmailQR) analysis.contentType = 'Email';
  else analysis.contentType = 'Text/Other';
  
  // Risk assessment logic for QR codes
  if (hasSuspiciousContent && !isLegitimateService) {
    riskLevel = 'dangerous';
    analysis.reputation = 'Contains malicious patterns';
  } else if (isURL && !analysis.hasEncryption) {
    riskLevel = 'suspicious';
    analysis.reputation = 'Unencrypted URL - potential risk';
  } else if (hasSuspiciousContent && isLegitimateService) {
    riskLevel = 'suspicious';
    analysis.reputation = 'Mixed signals - verify authenticity';
  } else if (isLegitimateService || isContactQR || isEmailQR) {
    riskLevel = 'safe';
    analysis.reputation = 'Appears legitimate';
  } else {
    riskLevel = 'suspicious';
    analysis.reputation = 'Unknown content - verify before use';
  }
  
  return { riskLevel, analysis };
};

const generateDetailedURLReport = (url: string, riskLevel: string, analysis: any): string => {
  const riskEmoji = {
    safe: '✅',
    suspicious: '⚠️',
    dangerous: '🚫'
  };
  
  let report = `${riskEmoji[riskLevel as keyof typeof riskEmoji]} **CYBERSECURITY ANALYSIS REPORT**\n\n`;
  
  // SSL/HTTPS Analysis
  report += `**🔒 SSL/HTTPS STATUS:**\n`;
  if (analysis.hasSSL) {
    report += `✅ HTTPS Protocol: Secure connection established\n`;
    report += `✅ Data transmission is encrypted\n`;
  } else {
    report += `❌ HTTP Protocol: Unencrypted connection\n`;
    report += `⚠️ Data transmitted in plain text - vulnerable to interception\n`;
  }
  
  // Domain Analysis
  report += `\n**🌐 DOMAIN REPUTATION:**\n`;
  report += `• Domain: ${analysis.domain}\n`;
  report += `• Protocol: ${analysis.protocol}\n`;
  report += `• Reputation Status: ${analysis.reputation}\n`;
  
  if (analysis.isLegitimateBase) {
    report += `• Base Domain: Recognized legitimate service\n`;
  }
  
  // Path Analysis
  report += `\n**🛣️ URL PATH ANALYSIS:**\n`;
  report += `• Path: ${analysis.path || '/'}\n`;
  
  if (analysis.hasSuspiciousPath) {
    report += `❌ SUSPICIOUS PATH DETECTED\n`;
    report += `• Contains keywords commonly used in phishing attacks\n`;
    report += `• May be attempting to mimic legitimate login/verification pages\n`;
  } else {
    report += `✅ Path structure appears normal\n`;
  }
  
  // Threat Assessment
  report += `\n**⚔️ THREAT ASSESSMENT:**\n`;
  
  if (riskLevel === 'dangerous') {
    if (analysis.isLegitimateBase && analysis.hasSuspiciousPath) {
      report += `🚨 **SIMULATED PHISHING ATTEMPT DETECTED**\n`;
      report += `• Legitimate domain with suspicious path structure\n`;
      report += `• Likely attempting to harvest credentials\n`;
      report += `• May be testing security awareness\n`;
    } else {
      report += `🚨 **HIGH RISK THREAT IDENTIFIED**\n`;
      report += `• Domain flagged for malicious activity\n`;
      report += `• Potential phishing, malware, or scam operation\n`;
      report += `• May attempt credential theft or malware installation\n`;
    }
  } else if (riskLevel === 'suspicious') {
    report += `⚠️ **MEDIUM RISK - EXERCISE CAUTION**\n`;
    report += `• Suspicious patterns detected in URL structure\n`;
    report += `• May be legitimate but requires verification\n`;
    report += `• Could be compromised or suspicious redirect\n`;
  } else {
    report += `✅ **LOW RISK - APPEARS SAFE**\n`;
    report += `• No immediate threats detected\n`;
    report += `• Standard security protocols in place\n`;
    report += `• Domain appears legitimate\n`;
  }
  
  // Attacker Tactics (if applicable)
  if (riskLevel !== 'safe') {
    report += `\n**🎯 POTENTIAL ATTACKER TACTICS:**\n`;
    if (analysis.hasSuspiciousPath) {
      report += `• **Social Engineering**: Using familiar paths to build false trust\n`;
      report += `• **Credential Harvesting**: Attempting to collect login information\n`;
      report += `• **Urgency Manipulation**: Creating false sense of urgency\n`;
    }
    if (!analysis.hasSSL) {
      report += `• **Data Interception**: Exploiting unencrypted connections\n`;
    }
    if (analysis.isSuspiciousDomain) {
      report += `• **Domain Spoofing**: Using similar-looking domains to deceive users\n`;
      report += `• **Malware Distribution**: Hosting malicious downloads\n`;
    }
  }
  
  // Risk Rating
  const riskRatings = {
    safe: '✅ **RISK RATING: LOW**',
    suspicious: '⚠️ **RISK RATING: MEDIUM**',
    dangerous: '🚫 **RISK RATING: HIGH**'
  };
  
  report += `\n${riskRatings[riskLevel as keyof typeof riskRatings]}\n`;
  
  // Safety Recommendations
  report += `\n**🛡️ SAFETY RECOMMENDATIONS:**\n`;
  
  if (riskLevel === 'dangerous') {
    report += `• ❌ DO NOT visit this URL\n`;
    report += `• 🚫 DO NOT enter any personal information\n`;
    report += `• 📞 Verify legitimacy through official channels\n`;
    report += `• 🚨 Report to security team if received via email/message\n`;
    report += `• 🔍 Use official websites by typing URLs directly\n`;
  } else if (riskLevel === 'suspicious') {
    report += `• ⚠️ Proceed with extreme caution\n`;
    report += `• 🔍 Verify URL authenticity through official sources\n`;
    report += `• 🚫 Avoid entering sensitive information\n`;
    report += `• 📱 Consider using official mobile apps instead\n`;
    report += `• 🛡️ Ensure antivirus protection is active\n`;
  } else {
    report += `• ✅ URL appears safe for browsing\n`;
    report += `• 🔒 Always verify SSL certificates on sensitive sites\n`;
    report += `• 👀 Stay alert for any unusual behavior\n`;
    report += `• 🔄 Keep browsers and security software updated\n`;
    report += `• 🚫 Never download unexpected files\n`;
  }
  
  report += `\n**📊 ANALYSIS COMPLETED**\n`;
  report += `Scan performed by AgentPhantom.AI Cybersecurity Engine`;
  
  return report;
};

const generateDetailedQRReport = (qrContent: string, riskLevel: string, analysis: any): string => {
  const riskEmoji = {
    safe: '✅',
    suspicious: '⚠️',
    dangerous: '🚫'
  };
  
  let report = `${riskEmoji[riskLevel as keyof typeof riskEmoji]} **QR CODE SECURITY ANALYSIS**\n\n`;
  
  // QR Content Analysis
  report += `**📱 QR CODE CONTENT:**\n`;
  report += `• Content Type: ${analysis.contentType}\n`;
  report += `• Content: ${qrContent.length > 100 ? qrContent.substring(0, 100) + '...' : qrContent}\n`;
  report += `• Reputation: ${analysis.reputation}\n`;
  
  // Security Features
  report += `\n**🔒 SECURITY FEATURES:**\n`;
  if (analysis.isURL) {
    if (analysis.hasEncryption) {
      report += `✅ HTTPS Encryption: Secure connection\n`;
    } else {
      report += `❌ No Encryption: HTTP connection (insecure)\n`;
    }
  }
  
  if (analysis.isLegitimateService) {
    report += `✅ Recognized Service: Known legitimate platform\n`;
  }
  
  // Content Type Specific Analysis
  report += `\n**📋 CONTENT TYPE ANALYSIS:**\n`;
  
  switch (analysis.contentType) {
    case 'URL':
      report += `🌐 **Website Link Detected**\n`;
      report += `• Directs to: ${qrContent}\n`;
      if (analysis.hasEncryption) {
        report += `• ✅ Uses secure HTTPS protocol\n`;
      } else {
        report += `• ❌ Uses insecure HTTP protocol\n`;
      }
      break;
      
    case 'WiFi Credentials':
      report += `📶 **WiFi Network Information**\n`;
      report += `• Contains network credentials\n`;
      report += `• ⚠️ Verify network authenticity before connecting\n`;
      break;
      
    case 'Contact Information':
      report += `👤 **Contact Card (vCard)**\n`;
      report += `• Contains personal/business contact details\n`;
      report += `• Generally safe content type\n`;
      break;
      
    case 'SMS/Phone':
      report += `📞 **Phone/SMS Information**\n`;
      report += `• Contains phone number or SMS data\n`;
      report += `• Verify number authenticity before calling\n`;
      break;
      
    case 'Email':
      report += `📧 **Email Address**\n`;
      report += `• Contains email contact information\n`;
      report += `• Generally safe content type\n`;
      break;
      
    default:
      report += `📄 **Text/Other Content**\n`;
      report += `• Contains text or unknown data format\n`;
      report += `• Requires manual verification\n`;
  }
  
  // Threat Assessment
  report += `\n**⚔️ THREAT ASSESSMENT:**\n`;
  
  if (riskLevel === 'dangerous') {
    report += `🚨 **HIGH RISK QR CODE DETECTED**\n`;
    report += `• Contains suspicious or malicious patterns\n`;
    report += `• May lead to phishing sites or malware\n`;
    report += `• Could be part of social engineering attack\n`;
    if (analysis.hasSuspiciousContent) {
      report += `• Flagged keywords detected in content\n`;
    }
  } else if (riskLevel === 'suspicious') {
    report += `⚠️ **MEDIUM RISK - VERIFICATION NEEDED**\n`;
    report += `• Content requires additional verification\n`;
    report += `• May be legitimate but shows concerning patterns\n`;
    if (!analysis.hasEncryption && analysis.isURL) {
      report += `• Uses unencrypted connection (HTTP)\n`;
    }
    report += `• Proceed with caution and verify authenticity\n`;
  } else {
    report += `✅ **LOW RISK - APPEARS SAFE**\n`;
    report += `• No immediate security threats detected\n`;
    report += `• Content appears legitimate\n`;
    if (analysis.isLegitimateService) {
      report += `• Links to recognized legitimate service\n`;
    }
  }
  
  // QR Code Attack Vectors
  if (riskLevel !== 'safe') {
    report += `\n**🎯 POTENTIAL QR CODE ATTACKS:**\n`;
    report += `• **QRishing**: QR code phishing to steal credentials\n`;
    report += `• **Malicious Redirects**: Leading to malware downloads\n`;
    report += `• **Social Engineering**: Exploiting trust in QR technology\n`;
    if (analysis.isURL) {
      report += `• **URL Manipulation**: Disguising malicious links\n`;
    }
    if (analysis.isWiFiQR) {
      report += `• **Rogue Networks**: Connecting to malicious WiFi\n`;
    }
  }
  
  // Risk Rating
  const riskRatings = {
    safe: '✅ **RISK RATING: LOW**',
    suspicious: '⚠️ **RISK RATING: MEDIUM**',
    dangerous: '🚫 **RISK RATING: HIGH**'
  };
  
  report += `\n${riskRatings[riskLevel as keyof typeof riskRatings]}\n`;
  
  // QR Code Safety Recommendations
  report += `\n**🛡️ QR CODE SAFETY RECOMMENDATIONS:**\n`;
  
  if (riskLevel === 'dangerous') {
    report += `• ❌ DO NOT scan this QR code with your device\n`;
    report += `• 🚫 DO NOT visit any links or follow instructions\n`;
    report += `• 🗑️ Delete or avoid the source of this QR code\n`;
    report += `• 🚨 Report suspicious QR codes to security team\n`;
    report += `• 🔍 Always verify QR code sources\n`;
  } else if (riskLevel === 'suspicious') {
    report += `• ⚠️ Verify QR code source before scanning\n`;
    report += `• 🔍 Check URL destination manually if possible\n`;
    report += `• 🚫 Avoid entering sensitive information\n`;
    report += `• 📱 Use QR scanner with preview functionality\n`;
    report += `• 🛡️ Ensure device security software is active\n`;
  } else {
    report += `• ✅ QR code appears safe to scan\n`;
    report += `• 👀 Always preview QR content before acting\n`;
    report += `• 🔒 Verify SSL certificates for website links\n`;
    report += `• 📱 Use trusted QR scanner applications\n`;
    report += `• 🚫 Never scan QR codes from untrusted sources\n`;
  }
  
  report += `\n**📊 QR CODE ANALYSIS COMPLETED**\n`;
  report += `Scan performed by AgentPhantom.AI QR Security Engine`;
  
  return report;
};

const fileAnalysisTemplates = [
  {
    riskLevel: 'safe' as const,
    report: `🛡️ **FILE ANALYSIS COMPLETE**

**File Structure Analysis:**
✅ Standard file format structure
✅ No embedded executables detected
✅ Digital signature validation passed
✅ No suspicious metadata found

**Behavioral Analysis:**
• File size within normal parameters
• Standard compression ratios
• No obfuscation detected
• Clean entropy analysis

**Recommendation:** This file appears to be safe. Always maintain current antivirus definitions and scan with multiple engines for maximum protection.`
  },
  {
    riskLevel: 'suspicious' as const,
    report: `⚠️ **FILE ANALYSIS COMPLETE**

**File Structure Analysis:**
⚠️ Unusual file structure patterns
⚠️ High entropy sections detected
⚠️ Potential packed/obfuscated content
✅ No immediate malware signatures

**Behavioral Analysis:**
• Suspicious file size for declared type
• Unusual metadata properties
• Potential steganography indicators
• Compressed archive anomalies

**Recommendation:** Exercise extreme caution. Scan with updated antivirus, use sandbox environment, and verify file source authenticity before execution.`
  },
  {
    riskLevel: 'dangerous' as const,
    report: `🚫 **MALWARE DETECTED - CRITICAL THREAT**

**File Structure Analysis:**
❌ Known malware signatures identified
❌ Suspicious executable code embedded
❌ Anti-analysis evasion techniques
❌ Network communication capabilities

**Behavioral Analysis:**
• Ransomware behavior patterns
• System modification capabilities  
• Data exfiltration potential
• Privilege escalation attempts

**CRITICAL WARNING:** This file contains active malware. DO NOT EXECUTE under any circumstances. Quarantine immediately and report to security team. Consider system compromise if already executed.`
  }
];

// Mock QR code content generation based on filename
const generateMockQRContent = (fileName: string): string => {
  const name = fileName.toLowerCase();
  
  if (name.includes('phish') || name.includes('malicious') || name.includes('scam')) {
    return 'https://fake-bank.com/urgent-verify-account?token=abc123&user=victim';
  } else if (name.includes('suspicious') || name.includes('short')) {
    return 'http://bit.ly/suspicious-link';
  } else if (name.includes('wifi')) {
    return 'WIFI:T:WPA;S:FreeWiFi;P:password123;;';
  } else if (name.includes('contact')) {
    return 'BEGIN:VCARD\nVERSION:3.0\nFN:John Doe\nTEL:+1234567890\nEMAIL:john@example.com\nEND:VCARD';
  } else if (name.includes('safe') || name.includes('google')) {
    return 'https://www.google.com/search?q=cybersecurity';
  } else {
    // Default safe content
    return 'https://agentphantom.ai/about';
  }
};

export const analyzeURL = async (url: string): Promise<ScanResult> => {
  // Simulate AI processing time
  await new Promise(resolve => setTimeout(resolve, 2000 + Math.random() * 3000));
  
  try {
    const { riskLevel, analysis } = analyzeURLSecurity(url);
    const report = generateDetailedURLReport(url, riskLevel, analysis);
    
    return {
      id: Date.now().toString(),
      type: 'url',
      target: url,
      report,
      riskLevel,
      timestamp: new Date(),
      userEmail: 'current.user@example.com', // In real app, get from auth context
      status: 'pending'
    };
  } catch (error) {
    // Fallback for invalid URLs
    return {
      id: Date.now().toString(),
      type: 'url',
      target: url,
      report: `❌ **URL ANALYSIS ERROR**\n\nInvalid URL format detected. Please ensure the URL includes the protocol (http:// or https://) and is properly formatted.\n\n**Example:** https://example.com`,
      riskLevel: 'suspicious',
      timestamp: new Date(),
      userEmail: 'current.user@example.com',
      status: 'pending'
    };
  }
};

export const analyzeFile = async (fileName: string, fileType: string): Promise<ScanResult> => {
  // Simulate AI processing time
  await new Promise(resolve => setTimeout(resolve, 1500 + Math.random() * 2500));
  
  // Mock risk assessment based on file characteristics
  let riskLevel: 'safe' | 'suspicious' | 'dangerous';
  
  if (fileName.includes('malware') || fileName.includes('virus') || fileType.includes('exe')) {
    riskLevel = 'dangerous';
  } else if (fileName.includes('suspicious') || fileType.includes('zip') || fileType.includes('rar')) {
    riskLevel = 'suspicious';
  } else {
    riskLevel = 'safe';
  }
  
  const template = fileAnalysisTemplates.find(t => t.riskLevel === riskLevel) || fileAnalysisTemplates[0];
  
  return {
    id: Date.now().toString(),
    type: 'file',
    target: `${fileName} (${fileType})`,
    report: template.report,
    riskLevel: template.riskLevel,
    timestamp: new Date(),
    userEmail: 'current.user@example.com', // In real app, get from auth context
    status: 'pending'
  };
};

export const analyzeQRCode = async (fileName: string, fileType: string): Promise<ScanResult> => {
  // Simulate AI processing time for QR code analysis
  await new Promise(resolve => setTimeout(resolve, 2000 + Math.random() * 3000));
  
  // Generate mock QR content based on filename
  const qrContent = generateMockQRContent(fileName);
  
  // Analyze the QR content for security risks
  const { riskLevel, analysis } = analyzeQRCodeSecurity(qrContent);
  const report = generateDetailedQRReport(qrContent, riskLevel, analysis);
  
  return {
    id: Date.now().toString(),
    type: 'qr',
    target: `QR Code: ${qrContent.length > 50 ? qrContent.substring(0, 50) + '...' : qrContent}`,
    report,
    riskLevel,
    timestamp: new Date(),
    userEmail: 'current.user@example.com', // In real app, get from auth context
    status: 'pending'
  };
};

export const generateBugAISuggestion = async (bugReport: BugReport): Promise<string> => {
  // Simulate AI processing time
  await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));
  
  // Mock AI suggestions based on bug content
  const suggestions = [
    'Update threat intelligence database with latest indicators',
    'Implement rate limiting to prevent timeout issues',
    'Add input validation for edge cases',
    'Optimize file processing algorithms for better performance',
    'Enhance error handling and user feedback mechanisms',
    'Review and update security scanning signatures',
    'Implement chunked processing for large files',
    'Add comprehensive logging for debugging purposes'
  ];
  
  return suggestions[Math.floor(Math.random() * suggestions.length)];
};