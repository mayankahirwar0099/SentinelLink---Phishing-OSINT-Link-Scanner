import type { DomFormAnalysis, HeuristicIndicator } from '../../types/scanner.js';

/**
 * Safely fetches raw HTML preview from the target URL with strict size & time boundaries.
 */
export async function fetchHtmlForInspection(url: string, timeoutMs = 2500): Promise<{ html: string; status: number }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SentinelLink-OSINT-Probe',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
    });

    clearTimeout(timer);

    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('text/html') && !contentType.includes('application/xhtml')) {
      return { html: '', status: response.status };
    }

    // Limit read to 150KB to keep memory light and fast
    const reader = response.body?.getReader();
    if (!reader) {
      const text = await response.text();
      return { html: text.slice(0, 150000), status: response.status };
    }

    const chunks: Uint8Array[] = [];
    let bytesReceived = 0;
    const maxBytes = 150000;

    while (bytesReceived < maxBytes) {
      const { done, value } = await reader.read();
      if (done || !value) break;
      chunks.push(value);
      bytesReceived += value.length;
    }

    const totalBuffer = new Uint8Array(bytesReceived);
    let offset = 0;
    for (const chunk of chunks) {
      totalBuffer.set(chunk, offset);
      offset += chunk.length;
    }

    const decoder = new TextDecoder('utf-8', { fatal: false });
    return { html: decoder.decode(totalBuffer), status: response.status };
  } catch {
    return { html: '', status: 0 };
  }
}

/**
 * Analyzes DOM structure, form inputs, hidden iframes, and fake login signatures.
 */
export function analyzeDomAndForms(params: {
  html: string;
  targetUrl: string;
  isHttps: boolean;
  apexDomain: string;
}): {
  analysis: DomFormAnalysis;
  indicators: HeuristicIndicator[];
} {
  const { html, targetUrl, isHttps, apexDomain } = params;

  if (!html || html.trim().length === 0) {
    const analysis: DomFormAnalysis = {
      htmlInspected: false,
      hasPasswordInput: false,
      hasUnencryptedPasswordInput: false,
      hiddenIframeDetected: false,
      hiddenIframeCount: 0,
      suspiciousFormAction: false,
      fakeLoginFormDetected: false,
      findings: ['Host returned no readable HTML body or connection timed out.'],
    };
    return {
      analysis,
      indicators: [
        {
          id: 'dom-inspection-skipped',
          module: 'DOM',
          title: 'HTML DOM Body Inspection Inaccessible',
          description: 'Web server did not provide a readable HTML response or rejected direct automated probing.',
          severity: 'INFO',
          points: 0,
          passed: true,
        },
      ],
    };
  }

  const findings: string[] = [];
  const lowerHtml = html.toLowerCase();

  // 1. Password Input Inspection
  const passwordInputRegex = /<input[^>]+type=["']?password["']?/i;
  const hasPasswordInput = passwordInputRegex.test(html);
  const hasUnencryptedPasswordInput = hasPasswordInput && !isHttps;

  if (hasPasswordInput) {
    if (hasUnencryptedPasswordInput) {
      findings.push('CRITICAL: Password input field detected on an unencrypted (HTTP) connection.');
    } else {
      findings.push('Password credential input field identified in DOM.');
    }
  }

  // 2. Hidden Iframe Detection
  // Matches hidden styling: display:none, visibility:hidden, opacity:0, or 0x0 geometry
  const hiddenIframeRegex = /<iframe[^>]*(style=["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|width\s*:\s*0|height\s*:\s*0)[^"']*|width=["']0["']|height=["']0["'])[^>]*>/gi;
  const hiddenIframeMatches = html.match(hiddenIframeRegex) || [];
  const hiddenIframeDetected = hiddenIframeMatches.length > 0;
  const hiddenIframeCount = hiddenIframeMatches.length;

  if (hiddenIframeDetected) {
    findings.push(`Detected ${hiddenIframeCount} concealed / hidden <iframe> element(s) commonly used for background credential interception, clickjacking, or silent token theft.`);
  }

  // 3. Form Action and Fake Login Form Detection
  // Check form action destinations
  const formActionRegex = /<form[^>]+action=["']([^"']+)["']/gi;
  let formMatch: RegExpExecArray | null;
  let suspiciousFormAction = false;

  while ((formMatch = formActionRegex.exec(html)) !== null) {
    const actionUrl = formMatch[1].trim();
    if (actionUrl.startsWith('http://') || actionUrl.startsWith('https://')) {
      try {
        const parsedAction = new URL(actionUrl);
        // Form submits data to an external apex domain or raw IP
        if (!parsedAction.hostname.includes(apexDomain)) {
          suspiciousFormAction = true;
          findings.push(`Form target action routes credentials off-domain to "${parsedAction.hostname}".`);
        }
      } catch {
        // Ignore parse error
      }
    }
  }

  // Page title extraction
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  const pageTitle = titleMatch ? titleMatch[1].trim() : undefined;

  // Fake login form heuristics: claims to be login or verification portal
  const loginKeywordsInDom = ['sign in', 'log in', 'enter password', 'verify identity', 'account locked', 'billing update', 'ssn', 'credit card'];
  const hasLoginText = loginKeywordsInDom.some((kw) => lowerHtml.includes(kw));
  const fakeLoginFormDetected = (hasPasswordInput || hasLoginText) && suspiciousFormAction;

  if (fakeLoginFormDetected) {
    findings.push('DOM structure exhibits high-confidence fake login form indicators.');
  }

  const analysis: DomFormAnalysis = {
    htmlInspected: true,
    hasPasswordInput,
    hasUnencryptedPasswordInput,
    hiddenIframeDetected,
    hiddenIframeCount,
    suspiciousFormAction,
    fakeLoginFormDetected,
    pageTitle,
    findings,
  };

  const indicators: HeuristicIndicator[] = [];

  // Password Input over Plaintext HTTP
  if (hasUnencryptedPasswordInput) {
    indicators.push({
      id: 'dom-plaintext-password',
      module: 'DOM',
      title: 'Insecure Unencrypted Password Form',
      description: 'The webpage requests user passwords or credentials over plaintext HTTP without TLS encryption. Severe data exposure risk.',
      severity: 'CRITICAL',
      points: 45,
      passed: false,
    });
  } else if (hasPasswordInput && suspiciousFormAction) {
    indicators.push({
      id: 'dom-suspicious-password-form',
      module: 'DOM',
      title: 'Off-Domain Credential Harvesting Form',
      description: 'Webpage contains password entry elements that post submitted data to an external, unverified destination.',
      severity: 'CRITICAL',
      points: 40,
      passed: false,
    });
  } else if (hasPasswordInput) {
    indicators.push({
      id: 'dom-password-input-detected',
      module: 'DOM',
      title: 'Credential Entry Fields Present',
      description: 'Webpage renders password input controls. Ensure target domain is strictly authentic before entering credentials.',
      severity: 'MEDIUM',
      points: 10,
      passed: false,
    });
  }

  // Hidden Iframe Indicator
  if (hiddenIframeDetected) {
    indicators.push({
      id: 'dom-hidden-iframe',
      module: 'DOM',
      title: `Concealed Iframe Detected (${hiddenIframeCount} hidden frame${hiddenIframeCount > 1 ? 's' : ''})`,
      description: 'The DOM contains zero-width or hidden <iframe> tags frequently deployed for clickjacking or drive-by payload delivery.',
      severity: 'HIGH',
      points: 25,
      passed: false,
    });
  } else {
    indicators.push({
      id: 'dom-hidden-iframe',
      module: 'DOM',
      title: 'Clean DOM Framing (No Concealed Iframes)',
      description: 'No hidden or zero-dimension iframes detected in the client document structure.',
      severity: 'INFO',
      points: 0,
      passed: true,
    });
  }

  // Suspicious Form Action Destination
  if (suspiciousFormAction) {
    indicators.push({
      id: 'dom-external-form-action',
      module: 'DOM',
      title: 'External Form Submissions',
      description: 'The HTML form submission endpoint points to a third-party server differing from the displayed landing page.',
      severity: 'HIGH',
      points: 30,
      passed: false,
    });
  }

  return { analysis, indicators };
}
