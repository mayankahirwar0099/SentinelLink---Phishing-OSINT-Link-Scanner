export type RiskLevel = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';

export type IndicatorModule = 'LEXICAL' | 'HOMOGLYPH' | 'DOM' | 'NETWORK_OSINT' | 'THREAT_FEED';

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
  spfRecord?: string;
  hasSpf: boolean;
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
  isRecentlyRegistered: boolean; // <= 30 days
  isBrandNew: boolean; // <= 7 days
  error?: string;
}

export interface HeuristicIndicator {
  id: string;
  module: IndicatorModule;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  points: number; // Numeric threat points contributed
  passed: boolean; // true = clean check, false = threat trigger
}

export interface LexicalAnalysis {
  hostnameEntropy: number;
  pathEntropy: number;
  subdomainCount: number;
  subdomains: string[];
  hasRawIp: boolean;
  tld: string;
  isAbuseTld: boolean;
  urlLength: number;
  hasAtSymbol: boolean;
  hyphenCount: number;
  digitCount: number;
}

export interface HomoglyphAnalysis {
  isPunycode: boolean;
  decodedPunycode?: string;
  hasMixedScript: boolean;
  confusableCharacters: string[];
  isTyposquat: boolean;
  matchedBrand?: string;
  officialDomain?: string;
  levenshteinDistance?: number;
  typosquatDetails?: string;
}

export interface DomFormAnalysis {
  htmlInspected: boolean;
  hasPasswordInput: boolean;
  hasUnencryptedPasswordInput: boolean;
  hiddenIframeDetected: boolean;
  hiddenIframeCount: number;
  suspiciousFormAction: boolean;
  fakeLoginFormDetected: boolean;
  pageTitle?: string;
  findings: string[];
}

export interface ThreatIntelAnalysis {
  urlhausMatched: boolean;
  urlhausThreat?: string;
  urlhausStatus?: string;
  phishtankMatched: boolean;
  phishtankTarget?: string;
  knownThreatListMatched: boolean;
  details: string[];
}

export interface DeterministicVerdict {
  verdict: RiskLevel;
  riskScore: number; // 0 - 100
  verdictTitle: string;
  plainEnglishSummary: string;
  dangerExplanation: string;
  attackVector: string;
  recommendedActions: string[];
  flaggedPointsTotal: number;
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
  verdict: DeterministicVerdict;
  lexical: LexicalAnalysis;
  homoglyph: HomoglyphAnalysis;
  dom: DomFormAnalysis;
  threatIntel: ThreatIntelAnalysis;
  redirects: RedirectHop[];
  dns: DnsInfo;
  ssl: SslInfo;
  rdap: RdapInfo;
  indicators: HeuristicIndicator[];
  executionTimeMs: number;
}
