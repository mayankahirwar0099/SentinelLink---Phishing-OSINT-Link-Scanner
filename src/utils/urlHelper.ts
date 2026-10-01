// Browser-safe and server-safe URL & text parsing helpers

export function extractUrlFromInput(input: string): { url: string; context?: string } {
  if (!input || typeof input !== 'string') {
    return { url: '' };
  }

  const trimmed = input.trim();
  if (!trimmed) {
    return { url: '' };
  }

  // Regex matching full URLs with protocol, or domain/IP with path or port
  const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:\/[^\s<>"'{}|\\^`]*)?|(?:(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:\/[^\s<>"'{}|\\^`]*)?/i;
  const match = trimmed.match(urlRegex);

  if (match && match[0]) {
    let rawUrl = match[0].trim();

    // Strip leading punctuation/quotes/brackets
    rawUrl = rawUrl.replace(/^[<"'({\[]+/, '');

    // Strip trailing punctuation common in SMS/emails (e.g. . , ! ? : ; " ')
    rawUrl = rawUrl.replace(/[.,!?;:"']+$/, '');

    // Strip unmatched trailing brackets/parentheses (handles (https://example.com) while preserving https://wiki/Path_(foo))
    const openParens = (rawUrl.match(/\(/g) || []).length;
    const closeParens = (rawUrl.match(/\)/g) || []).length;
    if (closeParens > openParens && rawUrl.endsWith(')')) {
      rawUrl = rawUrl.replace(/\)+$/, '');
    }

    const openBrackets = (rawUrl.match(/\[/g) || []).length;
    const closeBrackets = (rawUrl.match(/\]/g) || []).length;
    if (closeBrackets > openBrackets && rawUrl.endsWith(']')) {
      rawUrl = rawUrl.replace(/\]+$/, '');
    }

    const openBraces = (rawUrl.match(/\{/g) || []).length;
    const closeBraces = (rawUrl.match(/\}/g) || []).length;
    if (closeBraces > openBraces && rawUrl.endsWith('}')) {
      rawUrl = rawUrl.replace(/\}+$/, '');
    }

    if (rawUrl.endsWith('>')) {
      rawUrl = rawUrl.replace(/>+$/, '');
    }

    // Strip trailing punctuation again if punctuation preceded the closed bracket
    rawUrl = rawUrl.replace(/[.,!?;:"']+$/, '');

    // Ensure valid protocol
    if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) {
      rawUrl = 'https://' + rawUrl;
    }

    // Check if the input had surrounding SMS/email text context
    const context = trimmed.length > rawUrl.length + 5 ? trimmed : undefined;
    return { url: rawUrl, context };
  }

  // Fallback check: only treat as URL if there are no whitespace characters and contains a dot or port
  if (!/\s/.test(trimmed) && (trimmed.includes('.') || trimmed.includes(':'))) {
    let url = trimmed.replace(/^[<"'({\[]+/, '').replace(/[.,!?;:)>\]}"']+$/, '');
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }
    return { url };
  }

  return { url: '' };
}

export function getApexDomain(hostname: string): string {
  if (!hostname) return '';
  let cleanHost = hostname.toLowerCase().split(':')[0].trim();

  // Strip trailing DNS root dot if present (e.g. example.com.)
  cleanHost = cleanHost.replace(/\.+$/, '');

  // If it is a raw IPv4 or IPv6 address, return as-is
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(cleanHost) || cleanHost.includes(':') || cleanHost.startsWith('[')) {
    return cleanHost;
  }

  const parts = cleanHost.split('.');
  if (parts.length <= 2) return cleanHost;

  // Handle common second-level domains like co.uk, gov.uk, com.au, edu.au, etc.
  const secondLevel = parts.slice(-2).join('.');
  const special2ld = [
    'co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'ltd.uk', 'plc.uk', 'me.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
    'com.br', 'net.br', 'org.br', 'gov.br',
    'com.mx', 'org.mx', 'gob.mx', 'edu.mx',
    'co.in', 'net.in', 'org.in', 'gen.in', 'gov.in', 'edu.in',
    'co.za', 'org.za', 'gov.za',
    'com.sg', 'edu.sg', 'gov.sg',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
    'com.tw', 'org.tw', 'gov.tw',
    'co.kr', 'ne.kr', 'or.kr', 'go.kr',
    'com.tr', 'gov.tr', 'org.tr'
  ];

  if (special2ld.includes(secondLevel) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }

  return parts.slice(-2).join('.');
}
