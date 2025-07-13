# CyberIntel - AI-Powered Cybersecurity Platform

## Overview

**CyberIntel** is a real-time cybersecurity analysis platform built with React, TypeScript, and Tailwind CSS. It leverages advanced AI and machine learning to help users and security officers detect, analyze, and respond to digital threats including phishing, malware, vulnerabilities, data loss, and forensic events.

---

## Key Features

- **URL Scanner:** Analyze suspicious URLs for phishing, scams, and malware.
- **File Analyzer:** Scan uploaded files for malware, ransomware, and suspicious patterns.
- **QR Code Scanner:** Check QR codes for malicious links and unsafe content.
- **Threat Intelligence:** Real-time monitoring of network, endpoint, and malware threats with geolocation and attack path visualization.
- **Incident Response:** Automated incident creation, triage, containment, and reporting.
- **Vulnerability Management:** Assess, prioritize, and patch vulnerabilities using simulated integrations (Nessus, OpenVAS, Qualys).
- **Data Loss Prevention (DLP):** Monitor and block unauthorized transfers of sensitive data (PII, PCI, PHI).
- **Digital Forensics & Audit:** Manage forensic cases, evidence, chain of custody, and reconstruct timelines.
- **AI/ML Analytics:** Chatbot assistant, behavioral anomaly detection, log classification, and threat prediction.
- **Alert System:** Real-time alerts with sound, toast notifications, and email notifications to security officers.
- **Officer Panel:** Secure dashboard for authorized officers to review scans, bug reports, and incidents.
- **User Profile:** Manage account, sessions, activity logs, and security settings.
- **Bug Reporting:** Users can report security issues directly to the officer team.

---

## See This Website Running Publicly

You can view a live demo of CyberIntel at:

**[LIve App](https://cyberintela.netlify.app/)**

---

## How It Works

### 1. **User Authentication**
- Users and officers log in via secure portals.
- Officer authentication uses mock credentials for demo purposes.

### 2. **Scanning & Analysis**
- Users can scan URLs, files, and QR codes.
- AI engines analyze input and generate detailed security reports.
- High-risk findings automatically trigger alerts and email notifications.

### 3. **Threat Monitoring**
- Real-time dashboard visualizes threats, metrics, and attack paths.
- Threats are simulated for demo; real integrations can be added.

### 4. **Incident Response**
- Alerts can be converted into incidents.
- Incidents are auto-triaged, assigned, and tracked.
- Playbooks automate containment and remediation steps.

### 5. **Vulnerability Management**
- Vulnerabilities are assessed and prioritized based on CVSS and business impact.
- Patch management and compliance mapping are simulated.

### 6. **Data Loss Prevention**
- Content is scanned for sensitive data using regex and keyword patterns.
- Violations trigger alerts and can be blocked or quarantined.

### 7. **Digital Forensics**
- Forensic cases and evidence are managed with chain of custody.
- Audit logs and timelines help reconstruct events.

### 8. **AI/ML Integration**
- Chatbot answers security questions and assists with analysis.
- Behavioral models detect anomalies in user and network activity.

### 9. **Alert System**
- Alerts are shown in-app, with sound and toast notifications.
- Critical alerts send emails to officers (EmailJS integration).

---

## Getting Started

### Prerequisites

- Node.js (v18+ recommended)
- npm

### Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/vannoor/cyberintel.git
   cd cyberintel
   ```

2. **Install dependencies:**
   ```sh
   npm install
   ```

3. **Start the development server:**
   ```sh
   npm run dev
   ```

4. **Open in browser:**
   ```
   http://localhost:5173
   ```

---



---

## Email Alerts

- Uses [EmailJS](https://www.emailjs.com/) for sending real email notifications to officers.
- Officer emails are pre-configured for demo; update in `emailService.ts` for production.

---

## Customization

- **Add new officers:** Update mock officer list in `OfficerAuthContext.tsx`.
- **Change alert recipients:** Edit officer emails in `emailService.ts`.
- **Integrate real scanners:** Replace mock integrations in `vulnerabilityManagement.ts` and `threatIntelligence.ts`.
- **Update DLP policies:** Modify patterns and policies in `dlpEngine.ts`.

---

## Security Notes

- This is a demo platform. Authentication and scanning logic are simulated.
- For production, integrate with real security APIs and databases.

---


---

## Contact

- Email: vanursab71@gmail.com
- GitHub: [github.com/vannoor/cyberintel](https://github.com/vannoorsab)

---

**CyberIntel** — AI-powered digital defense