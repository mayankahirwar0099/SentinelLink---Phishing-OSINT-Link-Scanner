import dns from 'dns';
import tls from 'tls';
import net from 'net';
import { extractUrlFromInput, getApexDomain } from '../utils/urlHelper.js';
import type {
  DnsInfo,
  SslInfo,
  RdapInfo,
  RedirectHop,
  HeuristicIndicator,
  ScanResult,
} from '../types/scanner.js';
import { analyzeLexicalStructure } from './modules/lexicalModule.js';
import { analyzeHomoglyphsAndTypos } from './modules/homoglyphModule.js';
import { analyzeDomAndForms, fetchHtmlForInspection } from './modules/domModule.js';
import { queryThreatIntelFeeds } from './modules/threatIntelModule.js';
import { calculateCompositeVerdict } from './modules/scoringEngine.js';

export { extractUrlFromInput, getApexDomain };

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

/**
 * DNS & Mail Exchange / SPF OSINT Resolver
 */
export async function inspectDns(hostname: string): Promise<DnsInfo> {
  const dnsPromises = dns.promises;
  const result: DnsInfo = {
    resolvedIps: [],
    ipv6: [],
    mxRecords: [],
    nsRecords: [],
    txtRecords: [],
    reverseDns: [],
    hasSpf: false,
    hasMxRecords: false,
    resolved: false,
  };

  try {
    const cleanHost = hostname.split(':')[0];
    const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(cleanHost) || cleanHost.startsWith('[');

    if (isIpHost) {
      result.resolvedIps = [cleanHost];
      result.resolved = true;
      result.reverseDns = await withTimeout(
        dnsPromises.reverse(cleanHost.replace(/[[\]]/g, '')),
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
    result.txtRecords = (txtRecords || []).map((t) => t.join(' ')).slice(0, 8);
    result.hasMxRecords = result.mxRecords.length > 0;
    result.resolved = result.resolvedIps.length > 0 || result.ipv6.length > 0;

    // Check for SPF record in TXT records
    const spfMatch = result.txtRecords.find((txt) => txt.includes('v=spf1'));
    if (spfMatch) {
      result.hasSpf = true;
      result.spfRecord = spfMatch.replace(/^"|"$/g, '');
    }

    // Reverse DNS if IPv4 found
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

/**
 * RDAP OSINT Lookup (Domain Age, Registration Date)
 */
export async function inspectRdap(apexDomain: string): Promise<RdapInfo> {
  const result: RdapInfo = {
    domain: apexDomain,
    isRecentlyRegistered: false,
    isBrandNew: false,
  };

  try {
    const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(apexDomain) || apexDomain.startsWith('[');
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
        'User-Agent': 'SentinelLink-OSINT-Scanner/2.0',
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

/**
 * SSL / TLS Certificate Inspector
 */
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

/**
 * Redirect Tracing & HTTP Header Check
 */
export async function traceRedirects(
  initialUrl: string,
  maxHops = 4
): Promise<{ hops: RedirectHop[]; finalUrl: string }> {
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

/**
 * Complete Modular Pipeline Execution
 */
export async function performFullSecurityScan(params: {
  rawInput: string;
  extractedUrl: string;
  smsContext?: string;
  parsedUrl: URL;
}): Promise<ScanResult> {
  const startTime = Date.now();
  const { rawInput, extractedUrl, smsContext, parsedUrl } = params;

  const targetDomain = parsedUrl.hostname;
  const apexDomain = getApexDomain(targetDomain);
  const isHttps = parsedUrl.protocol === 'https:';

  // 1. Run independent modules concurrently
  const [
    lexicalResult,
    homoglyphResult,
    threatIntelResult,
    dnsResult,
    sslResult,
    rdapResult,
    redirectResult,
    htmlResult,
  ] = await Promise.all([
    analyzeLexicalStructure(parsedUrl),
    analyzeHomoglyphsAndTypos(parsedUrl, smsContext),
    queryThreatIntelFeeds(extractedUrl),
    inspectDns(targetDomain),
    inspectSsl(targetDomain, parsedUrl.port ? Number(parsedUrl.port) : 443),
    inspectRdap(apexDomain),
    traceRedirects(extractedUrl, 4),
    fetchHtmlForInspection(extractedUrl, 2500),
  ]);

  // 2. DOM and Form Analysis
  const domResult = analyzeDomAndForms({
    html: htmlResult.html,
    targetUrl: redirectResult.finalUrl,
    isHttps,
    apexDomain,
  });

  // 3. Compile OSINT Network Indicators
  const networkIndicators: HeuristicIndicator[] = [];

  // Domain Age
  if (rdapResult.domainAgeDays !== undefined) {
    if (rdapResult.domainAgeDays <= 7) {
      networkIndicators.push({
        id: 'osint-domain-brand-new',
        module: 'NETWORK_OSINT',
        title: `Brand New Domain (${rdapResult.domainAgeDays} days old)`,
        description: 'Domain was created within the past 7 days. Legitimate banking or postal platforms are never hosted on newly registered disposable domains.',
        severity: 'CRITICAL',
        points: 35,
        passed: false,
      });
    } else if (rdapResult.domainAgeDays <= 30) {
      networkIndicators.push({
        id: 'osint-domain-recent',
        module: 'NETWORK_OSINT',
        title: `Recently Registered Domain (${rdapResult.domainAgeDays} days old)`,
        description: 'Domain registration is under 30 days old. Statistically over 80% of phishing domains are discarded within this timeframe.',
        severity: 'HIGH',
        points: 20,
        passed: false,
      });
    } else {
      networkIndicators.push({
        id: 'osint-domain-established',
        module: 'NETWORK_OSINT',
        title: `Established Domain Age (${rdapResult.domainAgeDays} days old)`,
        description: `Domain has been actively registered for over ${Math.floor(rdapResult.domainAgeDays / 30)} months.`,
        severity: 'INFO',
        points: 0,
        passed: true,
      });
    }
  }

  // SSL Certificate
  if (!sslResult.hasSsl) {
    networkIndicators.push({
      id: 'osint-no-ssl',
      module: 'NETWORK_OSINT',
      title: 'Unencrypted Transmission (No TLS/SSL)',
      description: 'Host operates strictly over plaintext HTTP. Any submitted passwords, credit card numbers, or session cookies are fully exposed to interception.',
      severity: 'HIGH',
      points: 25,
      passed: false,
    });
  } else if (!sslResult.valid || sslResult.isExpired || sslResult.isSelfSigned) {
    networkIndicators.push({
      id: 'osint-invalid-ssl',
      module: 'NETWORK_OSINT',
      title: `Untrusted SSL Certificate (${sslResult.isExpired ? 'Expired' : sslResult.isSelfSigned ? 'Self-Signed' : 'Failed Public Trust'})`,
      description: sslResult.error || 'The certificate failed standard public CA trust validation.',
      severity: 'CRITICAL',
      points: 35,
      passed: false,
    });
  } else {
    networkIndicators.push({
      id: 'osint-valid-ssl',
      module: 'NETWORK_OSINT',
      title: 'Valid Trusted SSL/TLS Certificate',
      description: `Issued by ${sslResult.issuerOrg || 'Verified CA'}, valid for ${sslResult.daysRemaining ?? '?'} more days.`,
      severity: 'INFO',
      points: 0,
      passed: true,
    });
  }

  // DNS & MX
  if (!dnsResult.resolved) {
    networkIndicators.push({
      id: 'osint-dns-unresolved',
      module: 'NETWORK_OSINT',
      title: 'Unresolvable Hostname (NXDOMAIN)',
      description: 'Target hostname does not resolve to any public IP address. It may be sinkholed or taken down by registrars.',
      severity: 'MEDIUM',
      points: 15,
      passed: false,
    });
  } else if (!dnsResult.hasMxRecords && (homoglyphResult.analysis.isTyposquat || lexicalResult.analysis.isAbuseTld)) {
    networkIndicators.push({
      id: 'osint-zero-mx',
      module: 'NETWORK_OSINT',
      title: 'Zero Mail Exchange (MX) Infrastructure',
      description: 'Target domain cannot receive email. Common for disposable click-only attack websites imitating official organizations.',
      severity: 'LOW',
      points: 10,
      passed: false,
    });
  }

  // SPF Record Check
  if (dnsResult.hasSpf) {
    networkIndicators.push({
      id: 'osint-spf-configured',
      module: 'NETWORK_OSINT',
      title: 'Sender Policy Framework (SPF) Configured',
      description: 'Authoritative domain specifies authorized email senders via standard DNS SPF TXT records.',
      severity: 'INFO',
      points: 0,
      passed: true,
    });
  } else if (homoglyphResult.analysis.isTyposquat) {
    networkIndicators.push({
      id: 'osint-no-spf',
      module: 'NETWORK_OSINT',
      title: 'Missing SPF Anti-Spoofing Records',
      description: 'Domain lacks SPF verification, making it trivial for unauthorized third parties to forge sender addresses.',
      severity: 'LOW',
      points: 5,
      passed: false,
    });
  }

  // Redirection Hops
  if (redirectResult.hops.length > 2) {
    networkIndicators.push({
      id: 'osint-multiple-redirects',
      module: 'NETWORK_OSINT',
      title: `Multiple Redirection Hops (${redirectResult.hops.length} hops)`,
      description: 'The link traverses multiple intermediaries, frequently used to cloak the ultimate destination from automated security crawlers.',
      severity: 'MEDIUM',
      points: 15,
      passed: false,
    });
  }

  // 4. Combine all indicators
  const allIndicators: HeuristicIndicator[] = [
    ...lexicalResult.indicators,
    ...homoglyphResult.indicators,
    ...domResult.indicators,
    ...networkIndicators,
    ...threatIntelResult.indicators,
  ];

  // 5. Score using Deterministic Heuristics
  const verdict = calculateCompositeVerdict({
    indicators: allIndicators,
    targetDomain,
    apexDomain,
    lexical: lexicalResult.analysis,
    homoglyph: homoglyphResult.analysis,
    dom: domResult.analysis,
    threatIntel: threatIntelResult.analysis,
    dns: dnsResult,
    ssl: sslResult,
    rdap: rdapResult,
  });

  return {
    id: `scan-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    timestamp: new Date().toISOString(),
    originalInput: rawInput,
    extractedUrl,
    smsMessageContext: smsContext,
    normalizedUrl: parsedUrl.toString(),
    targetDomain,
    apexDomain,
    finalUrl: redirectResult.finalUrl,
    riskLevel: verdict.verdict,
    riskScore: verdict.riskScore,
    verdict,
    lexical: lexicalResult.analysis,
    homoglyph: homoglyphResult.analysis,
    dom: domResult.analysis,
    threatIntel: threatIntelResult.analysis,
    redirects: redirectResult.hops,
    dns: dnsResult,
    ssl: sslResult,
    rdap: rdapResult,
    indicators: allIndicators,
    executionTimeMs: Date.now() - startTime,
  };
}
