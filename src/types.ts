export interface User {
  id: string;
  fullName: string;
  email: string;
  profilePicture?: string | null;
  role?: string;
  department?: string;
  phone?: string;
  lastLogin?: Date;
}

export interface Officer {
  id: string;
  officerId: string;
  fullName: string;
  department: string;
  rank: string;
  email: string;
}

export interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => Promise<boolean>;
  signup: (fullName: string, email: string, password: string) => Promise<boolean>;
  logout: () => void;
  updateProfile: (updatedUser: Partial<User>) => Promise<boolean>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<boolean>;
  isAuthenticated: boolean;
}

export interface OfficerAuthContextType {
  officer: Officer | null;
  login: (officerId: string, password: string) => Promise<boolean>;
  logout: () => void;
  isAuthenticated: boolean;
  isInitialized: boolean;
}

export interface ScanResult {
  id: string;
  type: 'url' | 'file' | 'qr';
  target: string;
  report: string;
  riskLevel: 'safe' | 'suspicious' | 'dangerous';
  timestamp: Date;
  userEmail?: string;
  status: 'pending' | 'resolved';
  officerNotes?: string;
  suggestedFix?: string;
}

export interface BugReport {
  id: string;
  userId: string;
  userEmail: string;
  title: string;
  description: string;
  url?: string;
  file?: string;
  timestamp: Date;
  status: 'open' | 'assigned' | 'resolved';
  assignedOfficer?: string;
  officerNotes?: string;
  aiSuggestion?: string;
  resolution?: string;
}

export interface Alert {
  id: string;
  type: 'ThreatScan' | 'BugReport' | 'DLPViolation' | 'ForensicEvent';
  userEmail: string;
  timestamp: Date;
  message: string;
  status: 'unread' | 'read' | 'acknowledged';
  relatedId: string; // ID of the scan or bug report
  priority: 'low' | 'medium' | 'high' | 'critical';
}

export interface NavigationProps {
  currentPage: string;
  onNavigate: (page: string) => void;
}

export interface AlertContextType {
  alerts: Alert[];
  addAlert: (alert: Omit<Alert, 'id' | 'timestamp'>) => Alert;
  markAsRead: (alertId: string) => void;
  markAsAcknowledged: (alertId: string) => void;
  getUnreadCount: () => number;
  getCriticalCount: () => number;
  clearAllAlerts: () => void;
  deleteAlert: (alertId: string) => void;
}

export interface EmailNotification {
  to: string;
  subject: string;
  message: string;
  type: 'threat' | 'bug' | 'alert' | 'dlp' | 'forensic';
  timestamp: Date;
  status: 'sent' | 'pending' | 'failed';
}

// Incident Response Types
export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'new' | 'investigating' | 'contained' | 'resolved';
  priority: number;
  assignedTo: string;
  createdAt: Date;
  updatedAt: Date;
  affectedSystems: string[];
  containmentActions: ContainmentAction[];
  timeline: TimelineEntry[];
  evidence: Evidence[];
  relatedAlertId?: string;
  playbookExecutions?: PlaybookExecution[];
}

export interface ContainmentAction {
  id: string;
  type: 'isolate_endpoint' | 'block_ip' | 'block_domain' | 'quarantine_emails' | 'disable_account' | 'patch_system';
  target: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  timestamp: Date;
  details?: string;
  automatedBy?: string;
}

export interface TimelineEntry {
  timestamp: Date;
  action: string;
  user: string;
  details: string;
  type?: 'manual' | 'automated';
}

export interface Evidence {
  type: 'network_log' | 'file_hash' | 'email_headers' | 'url_analysis' | 'memory_dump' | 'registry_key';
  description: string;
  path: string;
  collectedAt?: Date;
  hash?: string;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  severity: string[];
  steps: PlaybookStep[];
  estimatedDuration: number; // in minutes
  lastUsed: Date;
  successRate?: number;
}

export interface PlaybookStep {
  id: string;
  name: string;
  type: 'containment' | 'investigation' | 'analysis' | 'communication' | 'remediation' | 'prevention' | 'compliance';
  automated: boolean;
  description: string;
  estimatedDuration?: number;
  dependencies?: string[];
  parameters?: Record<string, any>;
}

export interface PlaybookExecution {
  id: string;
  playbookId: string;
  incidentId: string;
  status: 'running' | 'completed' | 'failed' | 'paused';
  startedAt: Date;
  completedAt?: Date;
  executedBy: string;
  stepResults: PlaybookStepResult[];
  logs: string[];
}

export interface PlaybookStepResult {
  stepId: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  startedAt?: Date;
  completedAt?: Date;
  output?: any;
  error?: string;
}

export interface SOARWorkflow {
  id: string;
  name: string;
  description: string;
  triggers: WorkflowTrigger[];
  actions: WorkflowAction[];
  conditions: WorkflowCondition[];
  isActive: boolean;
  lastExecuted?: Date;
  executionCount: number;
}

export interface WorkflowTrigger {
  type: 'alert' | 'incident' | 'schedule' | 'manual';
  conditions: Record<string, any>;
}

export interface WorkflowAction {
  id: string;
  type: 'containment' | 'notification' | 'investigation' | 'analysis';
  parameters: Record<string, any>;
  automated: boolean;
}

export interface WorkflowCondition {
  field: string;
  operator: 'equals' | 'contains' | 'greater_than' | 'less_than';
  value: any;
}

// Vulnerability Management Types
export interface Vulnerability {
  id: string;
  cveId?: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  cvssScore: number;
  cvssVector?: string;
  exploitability: 'low' | 'medium' | 'high' | 'critical';
  impact: 'low' | 'medium' | 'high' | 'critical';
  affectedSystems: string[];
  affectedSoftware: string[];
  discoveredDate: Date;
  publishedDate?: Date;
  lastModified: Date;
  status: 'open' | 'in_progress' | 'patched' | 'mitigated' | 'accepted_risk';
  assignedTo?: string;
  dueDate?: Date;
  patchAvailable: boolean;
  patchComplexity: 'low' | 'medium' | 'high';
  businessCriticality: 'low' | 'medium' | 'high' | 'critical';
  exploitInWild: boolean;
  references: string[];
  tags: string[];
  remediationSteps?: string[];
  workarounds?: string[];
  riskScore: number; // Calculated risk score
  scannerSource: string;
  evidence?: VulnerabilityEvidence[];
}

export interface VulnerabilityEvidence {
  type: 'scan_result' | 'proof_of_concept' | 'exploit_code' | 'patch_info';
  description: string;
  data: any;
  timestamp: Date;
  source: string;
}

export interface VulnerabilityAssessment {
  id: string;
  name: string;
  description: string;
  targetSystems: string[];
  scanType: 'network' | 'web_app' | 'database' | 'infrastructure' | 'compliance';
  status: 'scheduled' | 'running' | 'completed' | 'failed' | 'cancelled';
  startTime?: Date;
  endTime?: Date;
  progress: number; // 0-100
  vulnerabilitiesFound: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  scannerUsed: string;
  configuration: any;
  results?: Vulnerability[];
  reportPath?: string;
}

export interface ScannerIntegration {
  id: string;
  name: string;
  type: 'nessus' | 'openvas' | 'qualys' | 'rapid7' | 'custom';
  status: 'active' | 'inactive' | 'error';
  endpoint: string;
  apiKey?: string;
  lastSync?: Date;
  capabilities: string[];
  configuration: any;
  credentialsConfigured: boolean;
  scanTemplates: ScanTemplate[];
}

export interface ScanTemplate {
  id: string;
  name: string;
  description: string;
  scanType: string;
  configuration: any;
  estimatedDuration: number;
  lastUsed?: Date;
}

export interface PatchManagement {
  id: string;
  vulnerabilityId: string;
  patchId: string;
  patchName: string;
  vendor: string;
  releaseDate: Date;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'available' | 'testing' | 'approved' | 'deployed' | 'failed';
  affectedSystems: string[];
  deploymentWindow?: Date;
  rollbackPlan?: string;
  testResults?: string;
  deploymentNotes?: string;
  approvedBy?: string;
  deployedBy?: string;
  deploymentDate?: Date;
  successRate?: number;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  description: string;
  version: string;
  requirements: ComplianceRequirement[];
  applicableSystems: string[];
  lastAssessment?: Date;
  complianceScore: number; // 0-100
  status: 'compliant' | 'non_compliant' | 'partial' | 'not_assessed';
}

export interface ComplianceRequirement {
  id: string;
  title: string;
  description: string;
  category: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  status: 'compliant' | 'non_compliant' | 'partial' | 'not_applicable';
  evidence?: string[];
  lastChecked?: Date;
  remediationSteps?: string[];
  assignedTo?: string;
  dueDate?: Date;
}

export interface RiskAssessment {
  vulnerabilityId: string;
  businessImpact: number; // 1-10
  exploitability: number; // 1-10
  assetCriticality: number; // 1-10
  threatLandscape: number; // 1-10
  compensatingControls: number; // 1-10
  overallRisk: number; // Calculated
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  justification: string;
  assessedBy: string;
  assessmentDate: Date;
}

// Data Loss Prevention Types
export interface DLPPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  dataTypes: DataClassification[];
  conditions: DLPCondition[];
  actions: DLPAction[];
  channels: DLPChannel[];
  exceptions: DLPException[];
  createdBy: string;
  createdAt: Date;
  lastModified: Date;
  violationCount: number;
  falsePositiveRate: number;
}

export interface DataClassification {
  id: string;
  name: string;
  type: 'pii' | 'phi' | 'pci' | 'financial' | 'intellectual_property' | 'confidential' | 'custom';
  patterns: RegexPattern[];
  keywords: string[];
  confidence: number; // 0-100
  sensitivity: 'public' | 'internal' | 'confidential' | 'restricted';
  description: string;
  examples: string[];
  regulatoryFramework?: string[];
}

export interface RegexPattern {
  pattern: string;
  description: string;
  confidence: number;
  examples: string[];
}

export interface DLPCondition {
  id: string;
  type: 'content_match' | 'file_type' | 'file_size' | 'user_group' | 'destination' | 'time_based';
  operator: 'equals' | 'contains' | 'regex' | 'greater_than' | 'less_than' | 'in_list';
  value: any;
  caseSensitive?: boolean;
  wholeWord?: boolean;
}

export interface DLPAction {
  id: string;
  type: 'block' | 'quarantine' | 'encrypt' | 'watermark' | 'notify' | 'log' | 'redirect';
  parameters: Record<string, any>;
  severity: 'low' | 'medium' | 'high' | 'critical';
  automated: boolean;
  requiresApproval?: boolean;
  approvers?: string[];
}

export interface DLPChannel {
  id: string;
  type: 'email' | 'web' | 'usb' | 'cloud' | 'network' | 'endpoint' | 'printer' | 'mobile';
  enabled: boolean;
  configuration: Record<string, any>;
  monitoringLevel: 'passive' | 'active' | 'blocking';
}

export interface DLPException {
  id: string;
  type: 'user' | 'group' | 'application' | 'destination' | 'time_window';
  value: string;
  reason: string;
  approvedBy: string;
  expiresAt?: Date;
  active: boolean;
}

export interface DLPViolation {
  id: string;
  policyId: string;
  policyName: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'detected' | 'investigating' | 'confirmed' | 'false_positive' | 'resolved';
  userId: string;
  userEmail: string;
  userName: string;
  department: string;
  timestamp: Date;
  channel: string;
  dataTypes: string[];
  matchedContent: DLPMatch[];
  destination?: string;
  fileInfo?: DLPFileInfo;
  actionTaken: string[];
  investigatedBy?: string;
  resolution?: string;
  falsePositive: boolean;
  riskScore: number;
  businessJustification?: string;
  approvedBy?: string;
  evidence: DLPEvidence[];
}

export interface DLPMatch {
  dataType: string;
  pattern: string;
  confidence: number;
  context: string;
  location: string;
  count: number;
}

export interface DLPFileInfo {
  fileName: string;
  fileType: string;
  fileSize: number;
  filePath: string;
  fileHash: string;
  encrypted: boolean;
  owner: string;
  lastModified: Date;
}

export interface DLPEvidence {
  type: 'screenshot' | 'file_copy' | 'network_log' | 'email_headers' | 'user_activity';
  description: string;
  path: string;
  timestamp: Date;
  hash?: string;
  metadata?: Record<string, any>;
}

export interface DLPDashboard {
  totalViolations: number;
  criticalViolations: number;
  violationsTrend: number; // percentage change
  topDataTypes: Array<{ type: string; count: number }>;
  topUsers: Array<{ user: string; violations: number }>;
  topChannels: Array<{ channel: string; violations: number }>;
  policyEffectiveness: Array<{ policy: string; violations: number; falsePositives: number }>;
  complianceScore: number;
  encryptionCoverage: number;
  recentViolations: DLPViolation[];
}

export interface EncryptionPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  scope: 'files' | 'emails' | 'databases' | 'network' | 'storage';
  algorithm: 'AES-256' | 'AES-128' | 'RSA-2048' | 'RSA-4096';
  keyManagement: 'automatic' | 'manual' | 'hsm';
  dataClassifications: string[];
  exceptions: string[];
  enforcementLevel: 'advisory' | 'mandatory';
  createdAt: Date;
  lastModified: Date;
}

export interface AccessControlPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  resourceType: 'file' | 'folder' | 'database' | 'application' | 'network';
  permissions: AccessPermission[];
  conditions: AccessCondition[];
  auditLevel: 'none' | 'basic' | 'detailed' | 'full';
  createdAt: Date;
  lastModified: Date;
}

export interface AccessPermission {
  principal: string; // user, group, or role
  principalType: 'user' | 'group' | 'role';
  permissions: string[]; // read, write, execute, delete, etc.
  granted: boolean;
  conditions?: AccessCondition[];
}

export interface AccessCondition {
  type: 'time' | 'location' | 'device' | 'network' | 'mfa_required';
  operator: 'equals' | 'in' | 'between' | 'requires';
  value: any;
}

export interface DataDiscovery {
  id: string;
  name: string;
  description: string;
  scope: string[];
  status: 'scheduled' | 'running' | 'completed' | 'failed';
  startTime?: Date;
  endTime?: Date;
  progress: number;
  dataFound: DataDiscoveryResult[];
  sensitiveDataCount: number;
  unprotectedDataCount: number;
  encryptedDataCount: number;
  lastRun: Date;
  nextRun?: Date;
  schedule?: string;
}

export interface DataDiscoveryResult {
  id: string;
  location: string;
  dataType: string;
  classification: string;
  sensitivity: string;
  size: number;
  encrypted: boolean;
  accessControls: boolean;
  owner: string;
  lastAccessed: Date;
  riskScore: number;
  recommendations: string[];
}

// Forensics & Audit Trail Types
export interface ForensicCase {
  id: string;
  caseNumber: string;
  title: string;
  description: string;
  status: 'open' | 'investigating' | 'analysis' | 'reporting' | 'closed';
  priority: 'low' | 'medium' | 'high' | 'critical';
  caseType: 'incident_response' | 'compliance_audit' | 'legal_discovery' | 'internal_investigation' | 'breach_analysis';
  investigator: string;
  assignedTeam: string[];
  createdAt: Date;
  updatedAt: Date;
  dueDate?: Date;
  relatedIncidents: string[];
  evidence: ForensicEvidence[];
  timeline: ForensicTimelineEntry[];
  chainOfCustody: ChainOfCustodyEntry[];
  findings: ForensicFinding[];
  report?: ForensicReport;
  legalHold: boolean;
  retentionPeriod: number; // days
  tags: string[];
  metadata: Record<string, any>;
}

export interface ForensicEvidence {
  id: string;
  caseId: string;
  evidenceNumber: string;
  type: 'disk_image' | 'memory_dump' | 'network_capture' | 'log_file' | 'email' | 'document' | 'database_export' | 'mobile_backup' | 'cloud_data' | 'registry_hive' | 'browser_artifacts';
  description: string;
  source: string;
  location: string;
  size: number;
  hash: EvidenceHash;
  collectedBy: string;
  collectedAt: Date;
  acquisitionMethod: string;
  acquisitionTool: string;
  verified: boolean;
  encrypted: boolean;
  compressionType?: string;
  metadata: EvidenceMetadata;
  chainOfCustody: ChainOfCustodyEntry[];
  analysis: EvidenceAnalysis[];
  tags: string[];
  legalHold: boolean;
  retentionDate: Date;
  accessLog: EvidenceAccessLog[];
}

export interface EvidenceHash {
  md5: string;
  sha1: string;
  sha256: string;
  sha512?: string;
  verifiedAt: Date;
  verifiedBy: string;
}

export interface EvidenceMetadata {
  originalPath?: string;
  fileSystem?: string;
  operatingSystem?: string;
  hostname?: string;
  username?: string;
  timezone?: string;
  createdDate?: Date;
  modifiedDate?: Date;
  accessedDate?: Date;
  permissions?: string;
  owner?: string;
  group?: string;
  attributes?: Record<string, any>;
}

export interface ChainOfCustodyEntry {
  id: string;
  evidenceId: string;
  action: 'collected' | 'transferred' | 'analyzed' | 'stored' | 'accessed' | 'copied' | 'returned' | 'destroyed';
  timestamp: Date;
  officer: string;
  location: string;
  purpose: string;
  notes?: string;
  witness?: string;
  signature: string;
  previousCustodian?: string;
  nextCustodian?: string;
  transferMethod?: string;
  storageLocation?: string;
  accessReason?: string;
  duration?: number; // minutes
}

export interface ForensicTimelineEntry {
  id: string;
  caseId: string;
  timestamp: Date;
  eventType: 'system_event' | 'user_action' | 'network_activity' | 'file_operation' | 'process_execution' | 'registry_change' | 'authentication' | 'application_event';
  source: string;
  description: string;
  details: Record<string, any>;
  evidenceId?: string;
  confidence: number; // 0-100
  tags: string[];
  correlatedEvents: string[];
  analysisNotes?: string;
  verified: boolean;
}

export interface EvidenceAnalysis {
  id: string;
  evidenceId: string;
  analysisType: 'file_carving' | 'keyword_search' | 'hash_analysis' | 'metadata_extraction' | 'timeline_analysis' | 'network_analysis' | 'malware_analysis' | 'steganography' | 'deleted_file_recovery';
  tool: string;
  version: string;
  startTime: Date;
  endTime?: Date;
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  results: AnalysisResult[];
  findings: string[];
  analyst: string;
  notes?: string;
  reportPath?: string;
}

export interface AnalysisResult {
  type: string;
  description: string;
  location: string;
  confidence: number;
  metadata: Record<string, any>;
  relatedEvidence?: string[];
}

export interface ForensicFinding {
  id: string;
  caseId: string;
  title: string;
  description: string;
  category: 'malware' | 'data_breach' | 'unauthorized_access' | 'policy_violation' | 'fraud' | 'intellectual_property_theft' | 'insider_threat' | 'compliance_violation';
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number; // 0-100
  evidence: string[]; // evidence IDs
  timeline: string[]; // timeline entry IDs
  impact: string;
  recommendations: string[];
  analyst: string;
  reviewedBy?: string;
  createdAt: Date;
  updatedAt: Date;
  status: 'draft' | 'review' | 'approved' | 'disputed';
}

export interface ForensicReport {
  id: string;
  caseId: string;
  title: string;
  executiveSummary: string;
  methodology: string;
  findings: string[];
  timeline: string;
  evidence: string[];
  conclusions: string;
  recommendations: string[];
  limitations: string;
  appendices: string[];
  author: string;
  reviewer?: string;
  approvedBy?: string;
  createdAt: Date;
  finalizedAt?: Date;
  version: number;
  format: 'pdf' | 'docx' | 'html';
  path: string;
  hash: string;
  digitalSignature?: string;
  legalReview: boolean;
  clientDeliverable: boolean;
}

export interface AuditLog {
  id: string;
  timestamp: Date;
  eventType: 'authentication' | 'authorization' | 'data_access' | 'data_modification' | 'system_change' | 'policy_change' | 'user_management' | 'evidence_access' | 'report_generation';
  userId: string;
  userEmail: string;
  userName: string;
  userRole: string;
  sourceIP: string;
  userAgent: string;
  sessionId: string;
  action: string;
  resource: string;
  resourceType: string;
  resourceId?: string;
  outcome: 'success' | 'failure' | 'partial';
  details: Record<string, any>;
  riskScore: number;
  geolocation?: {
    country: string;
    region: string;
    city: string;
    latitude: number;
    longitude: number;
  };
  deviceInfo?: {
    deviceType: string;
    operatingSystem: string;
    browser: string;
    fingerprint: string;
  };
  correlationId?: string;
  parentEventId?: string;
  tags: string[];
  retention: Date;
  archived: boolean;
}

export interface SystemActivity {
  id: string;
  timestamp: Date;
  hostname: string;
  processId: number;
  processName: string;
  parentProcessId?: number;
  userId: string;
  userName: string;
  eventType: 'process_start' | 'process_end' | 'file_access' | 'file_modify' | 'file_delete' | 'network_connection' | 'registry_access' | 'service_start' | 'service_stop' | 'login' | 'logout';
  details: Record<string, any>;
  commandLine?: string;
  workingDirectory?: string;
  environment?: Record<string, string>;
  networkConnections?: NetworkConnection[];
  fileOperations?: FileOperation[];
  registryOperations?: RegistryOperation[];
  hash?: string;
  signature?: string;
  reputation?: string;
  riskScore: number;
  tags: string[];
  correlatedEvents: string[];
}

export interface NetworkConnection {
  protocol: 'TCP' | 'UDP' | 'ICMP';
  sourceIP: string;
  sourcePort: number;
  destinationIP: string;
  destinationPort: number;
  direction: 'inbound' | 'outbound';
  bytesTransferred: number;
  duration: number;
  status: 'established' | 'closed' | 'failed';
}

export interface FileOperation {
  operation: 'create' | 'read' | 'write' | 'delete' | 'rename' | 'copy' | 'move';
  filePath: string;
  fileSize?: number;
  fileHash?: string;
  permissions?: string;
  owner?: string;
  group?: string;
  attributes?: string[];
}

export interface RegistryOperation {
  operation: 'create' | 'read' | 'write' | 'delete';
  keyPath: string;
  valueName?: string;
  valueType?: string;
  valueData?: string;
  previousValue?: string;
}

export interface ComplianceAudit {
  id: string;
  framework: 'SOX' | 'GDPR' | 'HIPAA' | 'PCI_DSS' | 'ISO_27001' | 'NIST' | 'FISMA' | 'COBIT';
  title: string;
  description: string;
  scope: string[];
  auditor: string;
  auditTeam: string[];
  startDate: Date;
  endDate?: Date;
  status: 'planning' | 'fieldwork' | 'reporting' | 'completed';
  requirements: ComplianceRequirement[];
  findings: ComplianceFinding[];
  evidence: string[]; // evidence IDs
  report?: ComplianceReport;
  remediation: RemediationPlan[];
  nextAudit?: Date;
  riskRating: 'low' | 'medium' | 'high' | 'critical';
  overallScore: number; // 0-100
}

export interface ComplianceFinding {
  id: string;
  auditId: string;
  requirementId: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'in_progress' | 'resolved' | 'accepted_risk';
  evidence: string[];
  recommendation: string;
  assignedTo?: string;
  dueDate?: Date;
  resolution?: string;
  resolvedBy?: string;
  resolvedAt?: Date;
}

export interface ComplianceReport {
  id: string;
  auditId: string;
  title: string;
  executiveSummary: string;
  scope: string;
  methodology: string;
  findings: ComplianceFinding[];
  recommendations: string[];
  conclusion: string;
  author: string;
  reviewer?: string;
  approvedBy?: string;
  createdAt: Date;
  finalizedAt?: Date;
  path: string;
  hash: string;
}

export interface RemediationPlan {
  id: string;
  findingId: string;
  title: string;
  description: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  assignedTo: string;
  dueDate: Date;
  estimatedEffort: number; // hours
  status: 'planned' | 'in_progress' | 'completed' | 'cancelled';
  progress: number; // 0-100
  tasks: RemediationTask[];
  dependencies: string[];
  riskReduction: number; // 0-100
  cost?: number;
  approvedBy?: string;
  completedAt?: Date;
}

export interface RemediationTask {
  id: string;
  title: string;
  description: string;
  assignedTo: string;
  dueDate: Date;
  status: 'pending' | 'in_progress' | 'completed';
  completedAt?: Date;
  notes?: string;
}

export interface EvidenceAccessLog {
  id: string;
  evidenceId: string;
  userId: string;
  userName: string;
  timestamp: Date;
  action: 'view' | 'download' | 'copy' | 'analyze' | 'modify' | 'delete';
  purpose: string;
  duration?: number; // minutes
  sourceIP: string;
  userAgent: string;
  approved: boolean;
  approvedBy?: string;
  notes?: string;
}

export interface LegalHold {
  id: string;
  title: string;
  description: string;
  legalCase: string;
  custodians: string[];
  dataSources: string[];
  keywords: string[];
  dateRange: {
    start: Date;
    end?: Date;
  };
  status: 'active' | 'released' | 'expired';
  createdBy: string;
  createdAt: Date;
  releasedAt?: Date;
  releasedBy?: string;
  preservationNotices: PreservationNotice[];
  evidence: string[]; // evidence IDs
  complianceChecks: LegalHoldCompliance[];
}

export interface PreservationNotice {
  id: string;
  legalHoldId: string;
  custodian: string;
  sentAt: Date;
  acknowledgedAt?: Date;
  method: 'email' | 'portal' | 'physical';
  content: string;
  reminders: Date[];
  status: 'sent' | 'acknowledged' | 'overdue';
}

export interface LegalHoldCompliance {
  id: string;
  legalHoldId: string;
  custodian: string;
  checkDate: Date;
  compliant: boolean;
  issues: string[];
  remediation?: string;
  checkedBy: string;
}

export interface ForensicDashboard {
  activeCases: number;
  evidenceItems: number;
  pendingAnalysis: number;
  complianceScore: number;
  recentActivity: AuditLog[];
  casesByStatus: Record<string, number>;
  evidenceByType: Record<string, number>;
  topInvestigators: Array<{ name: string; cases: number }>;
  auditTrends: Array<{ date: Date; events: number }>;
  riskMetrics: {
    highRiskEvents: number;
    failedLogins: number;
    privilegedAccess: number;
    dataExfiltration: number;
  };
}

// User Profile Types
export interface UserSettings {
  twoFactorEnabled: boolean;
  emailNotifications: boolean;
  smsNotifications: boolean;
  loginAlerts: boolean;
  sessionTimeout: number; // minutes
  allowedDevices: number;
  darkMode: boolean;
  language: string;
  timezone: string;
}

export interface UserSession {
  id: string;
  deviceType: string;
  browser: string;
  operatingSystem: string;
  ipAddress: string;
  location: string;
  lastActive: Date;
  isCurrentSession: boolean;
}

export interface UserActivity {
  id: string;
  action: string;
  timestamp: Date;
  ipAddress: string;
  deviceInfo: string;
  details: string;
}

export interface OTPVerification {
  email: string;
  code: string;
  expiresAt: Date;
  attempts: number;
  verified: boolean;
}