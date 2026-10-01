export type RiskLevel = 'SAFE' | 'LOW_RISK' | 'SUSPICIOUS' | 'HIGH_RISK';

export interface RedirectHop {
  url: string;
  statusCode: number;
  domain: string;
  ip?: string;
  protocol: string;
  isHttps: boolean;
}

export interface SslInfo {
  hasSsl: boolean;
  valid: boolean;
  issuerOrg?: string;
  issuerCommonName?: string;
  subjectCommonName?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  sanList?: string[];
  isSelfSigned?: boolean;
  isExpired?: boolean;
  error?: string;
}

export interface DnsInfo {
  resolvedIps: string[];
  ipv6: string[];
  mxRecords: { exchange: string; priority: number }[];
  nsRecords: string[];
  txtRecords: string[];
  reverseDns?: string[];
  hasMxRecords: boolean;
  resolved: boolean;
  error?: string;
}

export interface RdapInfo {
  domain: string;
  registrationDate?: string;
  expirationDate?: string;
  lastUpdatedDate?: string;
  domainAgeDays?: number;
  registrar?: string;
  status?: string[];
  isRecentlyRegistered: boolean; // < 30 days
  isBrandNew: boolean; // < 7 days
  error?: string;
}

export interface HeuristicIndicator {
  id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: 'DOMAIN' | 'SSL' | 'NETWORK' | 'BRAND' | 'REDIRECT' | 'CONTENT';
  passed: boolean; // true = clean, false = alert triggered
}

export interface BrandImpersonationCheck {
  isImpersonating: boolean;
  targetedBrand?: string;
  apexDomain: string;
  officialDomain?: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  notes?: string;
}

export interface AiThreatAnalysis {
  verdict: RiskLevel;
  riskScore: number; // 0 - 100
  title: string;
  plainEnglishSummary: string;
  dangerExplanation: string;
  attackVector: string; // e.g. "SMS Package Delivery Phishing (Smishing)"
  recommendedActions: string[];
  technicalHighlights: string[];
}

export interface ScanResult {
  id: string;
  timestamp: string;
  originalInput: string;
  extractedUrl: string;
  smsMessageContext?: string;
  normalizedUrl: string;
  targetDomain: string;
  apexDomain: string;
  finalUrl: string;
  riskLevel: RiskLevel;
  riskScore: number; // 0 - 100
  aiAnalysis: AiThreatAnalysis;
  redirects: RedirectHop[];
  dns: DnsInfo;
  ssl: SslInfo;
  rdap: RdapInfo;
  brandCheck: BrandImpersonationCheck;
  indicators: HeuristicIndicator[];
  executionTimeMs: number;
}
