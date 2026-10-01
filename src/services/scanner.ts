import dns from 'dns';
import tls from 'tls';
import http from 'http';
import https from 'https';
import net from 'net';
import { extractUrlFromInput, getApexDomain } from '../utils/urlHelper.js';
import type {
  DnsInfo,
  SslInfo,
  RdapInfo,
  RedirectHop,
  BrandImpersonationCheck,
  HeuristicIndicator,
} from '../types/scanner.js';

export { extractUrlFromInput, getApexDomain };

// Comprehensive list of high-value brands frequently impersonated in phishing & smishing
const MONITORED_BRANDS: Record<string, { officialDomains: string[]; keywords: string[] }> = {
  'USPS': {
    officialDomains: ['usps.com', 'uspspostb.com'],
    keywords: ['usps', 'postage', 'redelivery', 'parcel-usps', 'usps-tracking', 'postal-service', 'usps-delivery'],
  },
  'FedEx': {
    officialDomains: ['fedex.com'],
    keywords: ['fedex', 'fedx', 'fed-ex', 'fedex-tracking', 'fedex-delivery'],
  },
  'UPS': {
    officialDomains: ['ups.com'],
    keywords: ['ups-tracking', 'ups-delivery', 'upsdelivery', 'ups-parcel'],
  },
  'DHL': {
    officialDomains: ['dhl.com', 'dhl.de'],
    keywords: ['dhl', 'dhl-express', 'dhlexpress', 'dhl-tracking'],
  },
  'Royal Mail': {
    officialDomains: ['royalmail.com'],
    keywords: ['royalmail', 'royal-mail', 'royalmail-redelivery'],
  },
  'Netflix': {
    officialDomains: ['netflix.com'],
    keywords: ['netflix', 'netflix-verify', 'netfix', 'netflix-update', 'netflix-billing'],
  },
  'Apple': {
    officialDomains: ['apple.com', 'icloud.com'],
    keywords: ['appleid', 'icloud-find', 'apple-support', 'apple-security', 'apple-id', 'findmy-iphone'],
  },
  'PayPal': {
    officialDomains: ['paypal.com', 'paypal.me'],
    keywords: ['paypal', 'paypa1', 'paypal-resolution', 'paypal-security', 'paypal-verify'],
  },
  'Amazon': {
    officialDomains: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de'],
    keywords: ['amazon-security', 'amazon-order', 'amazon-verify', 'amazone', 'prime-update'],
  },
  'Chase': {
    officialDomains: ['chase.com'],
    keywords: ['chase-bank', 'chase-security', 'chase-alert', 'chase-verify', 'chase-fraud'],
  },
  'Bank of America': {
    officialDomains: ['bankofamerica.com', 'bofa.com'],
    keywords: ['bankofamerica', 'bofa-security', 'bofa-alert', 'bofa-verify', 'bofabank'],
  },
  'Wells Fargo': {
    officialDomains: ['wellsfargo.com'],
    keywords: ['wellsfargo', 'wf-alert', 'wellsfargo-verify', 'wf-security'],
  },
  'Citibank': {
    officialDomains: ['citi.com', 'citibank.com'],
    keywords: ['citibank', 'citi-alert', 'citi-verify'],
  },
  'IRS': {
    officialDomains: ['irs.gov'],
    keywords: ['irs-refund', 'irs-tax', 'irs-payment', 'irs-rebate', 'irs-gov-refund'],
  },
  'Toll Authority (SunPass / EZPass)': {
    officialDomains: ['sunpass.com', 'e-zpassny.com', 'ezpassva.com', 'tollroads.com'],
    keywords: ['sunpass', 'ezpass', 'e-zpass', 'toll-invoice', 'toll-violation', 'fastrak', 'toll-pay'],
  },
  'Microsoft': {
    officialDomains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'],
    keywords: ['microsoft-verify', 'office365-login', 'outlook-protection', 'ms-account', 'micosoft'],
  },
  'Google': {
    officialDomains: ['google.com', 'accounts.google.com'],
    keywords: ['google-verify', 'google-security-alert', 'gmail-account', 'google-alert'],
  },
  'Meta / Facebook': {
    officialDomains: ['meta.com', 'facebook.com', 'instagram.com'],
    keywords: ['meta-support', 'facebook-appeal', 'instagram-copyright', 'meta-security'],
  },
  'Venmo': {
    officialDomains: ['venmo.com'],
    keywords: ['venmo-security', 'venmo-verify', 'venmo-alert'],
  },
  'Coinbase': {
    officialDomains: ['coinbase.com'],
    keywords: ['coinbase-verify', 'coinbase-support', 'coinbase-wallet'],
  },
};

// Known high-abuse TLDs
const HIGH_ABUSE_TLDS = new Set([
  'top', 'xyz', 'click', 'work', 'loan', 'cf', 'gq', 'ml', 'ga', 'tk',
  'zip', 'mov', 'fit', 'buzz', 'rest', 'surf', 'cam', 'sbs', 'beauty', 'icu',
  'club', 'quest', 'cfd', 'mom', 'monster', 'support', 'live', 'online'
]);

// Known public URL shorteners
const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'ow.ly',
  'buff.ly', 'rb.gy', 'shorte.st', 'trib.al', 'rebrand.ly', 'bl.ink'
]);

// High-intent phishing path patterns
const SUSPICIOUS_PATH_PATTERNS = [
  /login/i, /signin/i, /verify/i, /verification/i, /account[-_]?update/i,
  /security[-_]?alert/i, /redelivery/i, /postage/i, /billing[-_]?update/i,
  /cancel[-_]?transfer/i, /wallet[-_]?restore/i, /unpaid[-_]?toll/i,
  /2fa/i, /otp/i, /password[-_]?reset/i, /confirm[-_]?identity/i
];

function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeoutPromise = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(fallback), ms);
  });
  return Promise.race([
    promise
      .then((res) => {
        clearTimeout(timer);
        return res;
      })
      .catch(() => fallback),
    timeoutPromise,
  ]);
}

// Check for homograph / punycode deceptive attacks
export function checkHomograph(hostname: string): { isHomograph: boolean; decoded?: string; details?: string } {
  try {
    if (hostname.startsWith('xn--') || hostname.includes('.xn--')) {
      return {
        isHomograph: true,
        details: 'Uses Internationalized Domain Names (IDN / Punycode) frequently exploited to visually impersonate familiar brands.',
      };
    }
    // Check for mixed non-ASCII characters mimicking standard ASCII
    const nonAscii = /[^\x00-\x7F]/;
    if (nonAscii.test(hostname)) {
      return {
        isHomograph: true,
        details: 'Contains non-ASCII Unicode characters that visually imitate standard Latin letters (homoglyph attack).',
      };
    }

    // Leetspeak / Typosquatting checks (e.g. paypa1.com, g00gle.com, netf1ix.com)
    const normalizedLeet = hostname
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/5/g, 's')
      .replace(/vv/g, 'w')
      .replace(/rn/g, 'm');

    for (const [brand, data] of Object.entries(MONITORED_BRANDS)) {
      for (const off of data.officialDomains) {
        const offName = off.split('.')[0];
        if (offName.length >= 4 && normalizedLeet.includes(offName) && !hostname.includes(offName)) {
          return {
            isHomograph: true,
            details: `Suspected typosquatting/leetspeak spoof of ${brand} (mimicking ${off}).`,
          };
        }
      }
    }
  } catch {
    // Ignore error
  }
  return { isHomograph: false };
}

// Check brand impersonation from URL and message context
export function detectBrandImpersonation(urlObj: URL, smsContext?: string): BrandImpersonationCheck {
  const hostname = urlObj.hostname.toLowerCase();
  const apex = getApexDomain(hostname);
  const fullPathAndHost = (urlObj.hostname + urlObj.pathname + urlObj.search).toLowerCase();
  const contextLower = (smsContext || '').toLowerCase();

  for (const [brand, data] of Object.entries(MONITORED_BRANDS)) {
    // Is it actually the official domain?
    const isOfficial = data.officialDomains.some(
      (dom) => apex === dom || hostname === dom || hostname.endsWith('.' + dom)
    );
    if (isOfficial) {
      continue;
    }

    // 1. Check if URL hostname or path contains brand keywords
    const matchedUrlKeyword = data.keywords.find((kw) => fullPathAndHost.includes(kw));
    if (matchedUrlKeyword) {
      return {
        isImpersonating: true,
        targetedBrand: brand,
        apexDomain: apex,
        officialDomain: data.officialDomains[0],
        confidence: 'HIGH',
        notes: `The link directs to "${apex}" which references "${brand}", but is NOT owned by ${data.officialDomains[0]}. This is an unauthorized brand impersonation.`,
      };
    }

    // 2. Check if the message pretext claims to be from the brand (e.g. SMS: "USPS: Your package is on hold")
    const matchedContextKeyword = data.keywords.find((kw) => contextLower.includes(kw));
    if (matchedContextKeyword) {
      return {
        isImpersonating: true,
        targetedBrand: brand,
        apexDomain: apex,
        officialDomain: data.officialDomains[0],
        confidence: 'HIGH',
        notes: `The message text claims to originate from ${brand}, but the destination address is "${apex}" instead of the authentic ${data.officialDomains[0]} service portal.`,
      };
    }
  }

  return {
    isImpersonating: false,
    apexDomain: apex,
    confidence: 'LOW',
  };
}

// DNS OSINT Resolver
export async function inspectDns(hostname: string): Promise<DnsInfo> {
  const dnsPromises = dns.promises;
  const result: DnsInfo = {
    resolvedIps: [],
    ipv6: [],
    mxRecords: [],
    nsRecords: [],
    txtRecords: [],
    reverseDns: [],
    hasMxRecords: false,
    resolved: false,
  };

  try {
    const cleanHost = hostname.split(':')[0];
    const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(cleanHost);

    if (isIpHost) {
      result.resolvedIps = [cleanHost];
      result.resolved = true;
      result.reverseDns = await withTimeout(
        dnsPromises.reverse(cleanHost),
        1000,
        [] as string[]
      );
      return result;
    }

    const apex = getApexDomain(cleanHost);

    // Parallel DNS lookups with strict 1500ms timeouts
    const [aRecords, aaaaRecords, mxRecords, nsRecords, txtRecords] = await Promise.all([
      withTimeout(dnsPromises.resolve4(cleanHost), 1500, [] as string[]),
      withTimeout(dnsPromises.resolve6(cleanHost), 1500, [] as string[]),
      withTimeout(dnsPromises.resolveMx(apex), 1500, [] as dns.MxRecord[]),
      withTimeout(dnsPromises.resolveNs(apex), 1500, [] as string[]),
      withTimeout(dnsPromises.resolveTxt(apex), 1500, [] as string[][]),
    ]);

    result.resolvedIps = aRecords || [];
    result.ipv6 = aaaaRecords || [];
    result.mxRecords = mxRecords || [];
    result.nsRecords = nsRecords || [];
    result.txtRecords = (txtRecords || []).map((t) => t.join(' ')).slice(0, 5);
    result.hasMxRecords = result.mxRecords.length > 0;
    result.resolved = result.resolvedIps.length > 0 || result.ipv6.length > 0;

    // Fast reverse DNS if IPv4 found
    if (result.resolvedIps.length > 0) {
      result.reverseDns = await withTimeout(
        dnsPromises.reverse(result.resolvedIps[0]),
        1000,
        [] as string[]
      );
    }
  } catch (err: unknown) {
    result.error = err instanceof Error ? err.message : 'DNS lookup failed';
  }

  return result;
}

// RDAP OSINT Lookup (Domain Age, Registration Date)
export async function inspectRdap(apexDomain: string): Promise<RdapInfo> {
  const result: RdapInfo = {
    domain: apexDomain,
    isRecentlyRegistered: false,
    isBrandNew: false,
  };

  try {
    const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(apexDomain);
    if (isIpHost) {
      result.error = 'Raw IP address; domain registry RDAP does not apply.';
      return result;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);

    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(apexDomain)}`, {
      signal: controller.signal,
      headers: {
        Accept: 'application/rdap+json, application/json',
        'User-Agent': 'SentinelLink-OSINT-Scanner/1.0',
      },
    });
    clearTimeout(timeout);

    if (response.ok) {
      const data = await response.json();

      if (Array.isArray(data.events)) {
        for (const ev of data.events) {
          if (ev.eventAction === 'registration') {
            result.registrationDate = ev.eventDate;
          } else if (ev.eventAction === 'expiration') {
            result.expirationDate = ev.eventDate;
          } else if (ev.eventAction === 'last changed' || ev.eventAction === 'last update') {
            result.lastUpdatedDate = ev.eventDate;
          }
        }
      }

      if (Array.isArray(data.entities)) {
        for (const ent of data.entities) {
          if (Array.isArray(ent.roles) && ent.roles.includes('registrar')) {
            result.registrar = ent.vcardArray?.[1]?.find((item: any) => item[0] === 'fn')?.[3] || ent.handle;
          }
        }
      }

      if (Array.isArray(data.status)) {
        result.status = data.status;
      }

      if (result.registrationDate) {
        const regTime = new Date(result.registrationDate).getTime();
        const now = Date.now();
        const ageDays = Math.floor((now - regTime) / (1000 * 60 * 60 * 24));
        result.domainAgeDays = Math.max(0, ageDays);

        if (ageDays <= 7) {
          result.isBrandNew = true;
          result.isRecentlyRegistered = true;
        } else if (ageDays <= 30) {
          result.isRecentlyRegistered = true;
        }
      }
    } else {
      result.error = `RDAP response code: ${response.status}`;
    }
  } catch (err: unknown) {
    result.error = err instanceof Error ? err.message : 'RDAP query failed';
  }

  return result;
}

// SSL / TLS Certificate Inspector
export async function inspectSsl(hostname: string, port = 443): Promise<SslInfo> {
  return new Promise((resolve) => {
    const cleanHost = hostname.split(':')[0];
    const isIp = net.isIP(cleanHost) !== 0;
    const timeout = 2000;
    let timer: NodeJS.Timeout;

    const socket = tls.connect(
      {
        host: cleanHost,
        port: port,
        servername: isIp ? undefined : cleanHost,
        rejectUnauthorized: false,
      },
      () => {
        clearTimeout(timer);
        try {
          const cert = socket.getPeerCertificate(true);
          const authorized = socket.authorized;
          const authError = socket.authorizationError;

          if (!cert || Object.keys(cert).length === 0) {
            socket.destroy();
            return resolve({
              hasSsl: false,
              valid: false,
              error: 'No SSL certificate returned by host.',
            });
          }

          const validFrom = cert.valid_from ? new Date(cert.valid_from).toISOString() : undefined;
          const validTo = cert.valid_to ? new Date(cert.valid_to).toISOString() : undefined;
          
          let daysRemaining: number | undefined;
          let isExpired = false;
          if (cert.valid_to) {
            const expiryTime = new Date(cert.valid_to).getTime();
            const now = Date.now();
            daysRemaining = Math.round((expiryTime - now) / (1000 * 60 * 60 * 24));
            isExpired = daysRemaining < 0;
          }

          const isSelfSigned = cert.issuer && cert.subject && cert.issuer.CN === cert.subject.CN;

          const sanList = cert.subjectaltname
            ? cert.subjectaltname.split(', ').map((s: string) => s.replace(/^DNS:/, ''))
            : [];

          const toStr = (val: string | string[] | undefined): string | undefined =>
            Array.isArray(val) ? val.join(', ') : val;

          socket.destroy();
          resolve({
            hasSsl: true,
            valid: authorized && !isExpired,
            issuerOrg: toStr(cert.issuer?.O) || toStr(cert.issuer?.CN),
            issuerCommonName: toStr(cert.issuer?.CN),
            subjectCommonName: toStr(cert.subject?.CN),
            validFrom,
            validTo,
            daysRemaining,
            sanList: sanList.slice(0, 10),
            isSelfSigned,
            isExpired,
            error: authError ? String(authError) : undefined,
          });
        } catch (err: unknown) {
          socket.destroy();
          resolve({
            hasSsl: true,
            valid: false,
            error: err instanceof Error ? err.message : 'Error reading certificate',
          });
        }
      }
    );

    socket.on('error', (err) => {
      clearTimeout(timer);
      socket.destroy();
      resolve({
        hasSsl: false,
        valid: false,
        error: err.message,
      });
    });

    timer = setTimeout(() => {
      socket.destroy();
      resolve({
        hasSsl: false,
        valid: false,
        error: 'TLS handshake timed out after 2s',
      });
    }, timeout);
  });
}

// Redirect Tracing & HTTP Header Check
export async function traceRedirects(initialUrl: string, maxHops = 4): Promise<{ hops: RedirectHop[]; finalUrl: string }> {
  const hops: RedirectHop[] = [];
  const visited = new Set<string>();
  let currentUrl = initialUrl;

  for (let i = 0; i < maxHops; i++) {
    if (visited.has(currentUrl)) {
      break;
    }
    visited.add(currentUrl);

    try {
      const urlObj = new URL(currentUrl);
      const isHttps = urlObj.protocol === 'https:';

      const response = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(1800),
        headers: {
          'User-Agent':
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1 SentinelScanner',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });

      hops.push({
        url: currentUrl,
        statusCode: response.status,
        domain: urlObj.hostname,
        protocol: urlObj.protocol,
        isHttps,
      });

      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const locationHeader = response.headers.get('location');
        if (locationHeader) {
          currentUrl = new URL(locationHeader, currentUrl).toString();
          continue;
        }
      }

      break;
    } catch {
      try {
        const parsed = new URL(currentUrl);
        hops.push({
          url: currentUrl,
          statusCode: 0,
          domain: parsed.hostname,
          protocol: parsed.protocol,
          isHttps: parsed.protocol === 'https:',
        });
      } catch {
        // Ignore
      }
      break;
    }
  }

  return {
    hops,
    finalUrl: currentUrl,
  };
}

// Compile Comprehensive Heuristic Threat Indicators
export function evaluateIndicators(params: {
  urlObj: URL;
  finalUrlObj: URL;
  rawInput: string;
  dns: DnsInfo;
  ssl: SslInfo;
  rdap: RdapInfo;
  brandCheck: BrandImpersonationCheck;
  hopsCount: number;
}): { indicators: HeuristicIndicator[]; computedScore: number } {
  const { urlObj, finalUrlObj, rawInput, dns, ssl, rdap, brandCheck, hopsCount } = params;
  const indicators: HeuristicIndicator[] = [];
  let riskScore = 0;

  const hostname = urlObj.hostname.toLowerCase();
  const apex = getApexDomain(hostname);
  const tld = apex.split('.').pop() || '';
  const pathname = urlObj.pathname.toLowerCase();
  const search = urlObj.search.toLowerCase();
  const fullPath = pathname + search;

  // 1. Brand Impersonation
  if (brandCheck.isImpersonating) {
    indicators.push({
      id: 'brand-spoof',
      title: `Deceptive Brand Impersonation (${brandCheck.targetedBrand})`,
      description: brandCheck.notes || `The site pretends to belong to ${brandCheck.targetedBrand}, but is hosted on "${apex}" instead of official ${brandCheck.officialDomain}.`,
      severity: 'CRITICAL',
      category: 'BRAND',
      passed: false,
    });
    riskScore += 50;
  } else {
    indicators.push({
      id: 'brand-spoof',
      title: 'No Brand Impersonation Signatures',
      description: 'Host does not match known trademark brand-spoofing patterns.',
      severity: 'INFO',
      category: 'BRAND',
      passed: true,
    });
  }

  // 2. Homograph / Punycode
  const homograph = checkHomograph(hostname);
  if (homograph.isHomograph) {
    indicators.push({
      id: 'homograph-alert',
      title: 'IDN / Punycode Homograph Deception',
      description: homograph.details || 'The hostname uses deceptive non-standard character encoding.',
      severity: 'CRITICAL',
      category: 'DOMAIN',
      passed: false,
    });
    riskScore += 40;
  }

  // 3. Userinfo / @ Symbol Trick (must be part of the URL address itself)
  const hasAtTrick = Boolean(urlObj.username) || (urlObj.href.includes('@') && urlObj.href.indexOf('@') < urlObj.href.indexOf(urlObj.hostname));
  if (hasAtTrick) {
    indicators.push({
      id: 'userinfo-at-symbol',
      title: 'Embedded Credentials / @ Symbol Deception',
      description: 'The URL uses the @ symbol to obfuscate the real destination host from the user.',
      severity: 'CRITICAL',
      category: 'CONTENT',
      passed: false,
    });
    riskScore += 45;
  }

  // 4. Domain Age
  if (rdap.domainAgeDays !== undefined) {
    if (rdap.domainAgeDays <= 7) {
      indicators.push({
        id: 'domain-age-critical',
        title: `Brand New Domain (${rdap.domainAgeDays} days old)`,
        description: 'Domain was created within the last 7 days. Legitimate banking or service links are never newly created throwaway domains.',
        severity: 'CRITICAL',
        category: 'DOMAIN',
        passed: false,
      });
      riskScore += 40;
    } else if (rdap.domainAgeDays <= 30) {
      indicators.push({
        id: 'domain-age-high',
        title: `Recently Registered Domain (${rdap.domainAgeDays} days old)`,
        description: 'Domain is less than 30 days old. Over 85% of malicious phishing domains are discarded within 30 days.',
        severity: 'HIGH',
        category: 'DOMAIN',
        passed: false,
      });
      riskScore += 25;
    } else {
      indicators.push({
        id: 'domain-age-ok',
        title: `Established Domain Age (${rdap.domainAgeDays} days old)`,
        description: `Domain has been registered for over ${Math.floor(rdap.domainAgeDays / 30)} months.`,
        severity: 'INFO',
        category: 'DOMAIN',
        passed: true,
      });
    }
  }

  // 5. High Abuse TLD
  if (HIGH_ABUSE_TLDS.has(tld)) {
    indicators.push({
      id: 'abuse-tld',
      title: `High-Risk TLD (Top-Level Domain .${tld})`,
      description: `The .${tld} extension has a statistically elevated abuse rate according to threat intelligence telemetry.`,
      severity: 'HIGH',
      category: 'DOMAIN',
      passed: false,
    });
    riskScore += 20;
  }

  // 6. IP Address used as Hostname
  const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname.split(':')[0]);
  if (isIpHost) {
    indicators.push({
      id: 'ip-hostname',
      title: 'Raw IP Address Hostname',
      description: 'The URL uses a raw IP address instead of a registered domain name, heavily indicative of malicious infrastructure or C2.',
      severity: 'CRITICAL',
      category: 'NETWORK',
      passed: false,
    });
    riskScore += 40;
  }

  // 7. Excessive Subdomain Depth or Deceptive Brand in Subdomain
  const subdomains = hostname.split('.');
  const brandKeywords = [
    'paypal', 'chase', 'usps', 'fedex', 'ups', 'netflix', 'apple', 'amazon',
    'bofa', 'bankofamerica', 'irs', 'sunpass', 'citibank', 'wellsfargo', 'coinbase'
  ];
  const hasDeceptiveSubdomainBrand = subdomains.slice(0, -2).some((sub) =>
    brandKeywords.some((brand) => sub.includes(brand))
  );

  if (hasDeceptiveSubdomainBrand) {
    indicators.push({
      id: 'subdomain-brand-spoof',
      title: 'Deceptive Brand Prefix in Subdomain',
      description: `Attackers inserted a recognized brand keyword into the subdomain to fool users whose browsers truncate long URLs.`,
      severity: 'CRITICAL',
      category: 'DOMAIN',
      passed: false,
    });
    riskScore += 35;
  } else if (subdomains.length >= 4 && !isIpHost) {
    indicators.push({
      id: 'excessive-subdomains',
      title: 'Excessive Subdomain Stacking',
      description: `Hostname contains ${subdomains.length} dotted levels. Attackers stack subdomains to trick mobile users who only see the first part on phone screens.`,
      severity: 'HIGH',
      category: 'DOMAIN',
      passed: false,
    });
    riskScore += 20;
  }

  // 8. Suspicious Path Harvesting Keywords
  const matchedPathPattern = SUSPICIOUS_PATH_PATTERNS.find((regex) => regex.test(fullPath));
  if (matchedPathPattern) {
    // If on a high-abuse TLD or newly registered or brand spoof
    if (HIGH_ABUSE_TLDS.has(tld) || brandCheck.isImpersonating || (rdap.domainAgeDays !== undefined && rdap.domainAgeDays <= 60)) {
      indicators.push({
        id: 'suspicious-path-harvest',
        title: 'Credential / Sensitive Action Harvesting Path',
        description: `URL path contains sensitive keywords (${fullPath.substring(0, 30)}...) on unverified infrastructure.`,
        severity: 'HIGH',
        category: 'CONTENT',
        passed: false,
      });
      riskScore += 25;
    }
  }

  // 9. Known Shortener Link
  if (KNOWN_SHORTENERS.has(apex)) {
    indicators.push({
      id: 'url-shortener',
      title: 'Shortened Relayed Link',
      description: `The link uses a shortening service (${apex}) that obscures the final destination until resolved.`,
      severity: 'MEDIUM',
      category: 'REDIRECT',
      passed: false,
    });
    riskScore += 15;
  }

  // 10. Non-Standard Port
  if (urlObj.port && !['80', '443'].includes(urlObj.port)) {
    indicators.push({
      id: 'port-anomaly',
      title: `Non-Standard Port (Port ${urlObj.port})`,
      description: `Link connects on custom port ${urlObj.port}, uncharacteristic of legitimate consumer or banking platforms.`,
      severity: 'HIGH',
      category: 'NETWORK',
      passed: false,
    });
    riskScore += 25;
  }

  // 11. SSL / TLS Verification
  if (!ssl.hasSsl) {
    indicators.push({
      id: 'no-ssl',
      title: 'Unencrypted Connection (No SSL/TLS)',
      description: 'Target site does not provide HTTPS encryption. Any passwords or credentials entered would travel in plain text.',
      severity: 'HIGH',
      category: 'SSL',
      passed: false,
    });
    riskScore += 25;
  } else if (!ssl.valid || ssl.isExpired || ssl.isSelfSigned) {
    indicators.push({
      id: 'invalid-ssl',
      title: `Invalid SSL Certificate (${ssl.isExpired ? 'Expired' : ssl.isSelfSigned ? 'Self-Signed' : 'Untrusted Authority'})`,
      description: ssl.error || 'The certificate failed standard public trust validation.',
      severity: 'CRITICAL',
      category: 'SSL',
      passed: false,
    });
    riskScore += 35;
  } else {
    indicators.push({
      id: 'ssl-valid',
      title: 'Valid SSL/TLS Certificate',
      description: `Issued by ${ssl.issuerOrg || 'trusted certificate authority'}, valid for ${ssl.daysRemaining ?? '?'} more days.`,
      severity: 'INFO',
      category: 'SSL',
      passed: true,
    });
  }

  // 12. DNS Resolution & MX Records
  if (!dns.resolved) {
    indicators.push({
      id: 'dns-unresolved',
      title: 'Unresolvable Hostname (NXDOMAIN)',
      description: 'The hostname does not currently resolve to any public IP address. It may be taken down or sinkholed.',
      severity: 'MEDIUM',
      category: 'NETWORK',
      passed: false,
    });
    riskScore += 15;
  } else if (!dns.hasMxRecords) {
    if (brandCheck.isImpersonating || HIGH_ABUSE_TLDS.has(tld)) {
      indicators.push({
        id: 'no-mx',
        title: 'Zero Mail Exchange (MX) Infrastructure',
        description: 'Domain has no configured email servers, characteristic of disposable click-only attack websites.',
        severity: 'LOW',
        category: 'NETWORK',
        passed: false,
      });
      riskScore += 10;
    }
  }

  // 13. Redirect Hops (Unshortening)
  if (hopsCount > 2) {
    indicators.push({
      id: 'multiple-redirects',
      title: `Multiple Redirection Hops (${hopsCount} hops)`,
      description: 'The link traverses multiple intermediaries, frequently used to cloak the ultimate malicious destination from automated scanners.',
      severity: 'MEDIUM',
      category: 'REDIRECT',
      passed: false,
    });
    riskScore += 15;
  }

  // Clamp score
  const computedScore = Math.min(100, Math.max(0, riskScore));

  return { indicators, computedScore };
}
