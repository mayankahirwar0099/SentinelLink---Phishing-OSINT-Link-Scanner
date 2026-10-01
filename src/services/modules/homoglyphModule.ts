import url from 'url';
import type { HomoglyphAnalysis, HeuristicIndicator } from '../../types/scanner.js';
import { getApexDomain } from '../../utils/urlHelper.js';

// Top recognized target brands and their official root domains
export const TOP_TARGET_BRANDS: Array<{
  brand: string;
  officialDomains: string[];
  canonicalSlug: string;
  keywords: string[];
}> = [
  { brand: 'PayPal', officialDomains: ['paypal.com', 'paypal.me'], canonicalSlug: 'paypal', keywords: ['paypal', 'paypa1'] },
  { brand: 'Google', officialDomains: ['google.com', 'accounts.google.com'], canonicalSlug: 'google', keywords: ['google', 'g00gle', 'goog1e', 'gmail'] },
  { brand: 'Microsoft', officialDomains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'], canonicalSlug: 'microsoft', keywords: ['microsoft', 'micros0ft', 'office365', 'outlook'] },
  { brand: 'Apple', officialDomains: ['apple.com', 'icloud.com'], canonicalSlug: 'apple', keywords: ['apple', 'appleid', 'icloud', 'findmy'] },
  { brand: 'Amazon', officialDomains: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de'], canonicalSlug: 'amazon', keywords: ['amazon', 'amazone', 'arnazon', 'prime'] },
  { brand: 'Netflix', officialDomains: ['netflix.com'], canonicalSlug: 'netflix', keywords: ['netflix', 'netf1ix', 'netfix'] },
  { brand: 'Chase', officialDomains: ['chase.com'], canonicalSlug: 'chase', keywords: ['chase', 'chasebank'] },
  { brand: 'Bank of America', officialDomains: ['bankofamerica.com', 'bofa.com'], canonicalSlug: 'bankofamerica', keywords: ['bankofamerica', 'bofa'] },
  { brand: 'Wells Fargo', officialDomains: ['wellsfargo.com'], canonicalSlug: 'wellsfargo', keywords: ['wellsfargo', 'wellsfarg0', 'wfbank'] },
  { brand: 'Citibank', officialDomains: ['citi.com', 'citibank.com'], canonicalSlug: 'citibank', keywords: ['citi', 'citibank'] },
  { brand: 'Coinbase', officialDomains: ['coinbase.com'], canonicalSlug: 'coinbase', keywords: ['coinbase', 'coinba5e'] },
  { brand: 'USPS', officialDomains: ['usps.com'], canonicalSlug: 'usps', keywords: ['usps', 'postage', 'redelivery', 'parcel-usps'] },
  { brand: 'FedEx', officialDomains: ['fedex.com'], canonicalSlug: 'fedex', keywords: ['fedex', 'fedx', 'fed-ex'] },
  { brand: 'UPS', officialDomains: ['ups.com'], canonicalSlug: 'ups', keywords: ['ups', 'ups-tracking', 'ups-parcel'] },
  { brand: 'DHL', officialDomains: ['dhl.com'], canonicalSlug: 'dhl', keywords: ['dhl', 'dhl-express'] },
  { brand: 'IRS', officialDomains: ['irs.gov'], canonicalSlug: 'irs', keywords: ['irs', 'irs-tax', 'irs-gov'] },
  { brand: 'SunPass / Tolls', officialDomains: ['sunpass.com', 'e-zpassny.com'], canonicalSlug: 'sunpass', keywords: ['sunpass', 'ezpass', 'toll-invoice'] },
  { brand: 'Meta / Facebook', officialDomains: ['facebook.com', 'meta.com', 'instagram.com'], canonicalSlug: 'facebook', keywords: ['facebook', 'faceb00k', 'instagram', 'meta'] },
  { brand: 'Venmo', officialDomains: ['venmo.com'], canonicalSlug: 'venmo', keywords: ['venmo'] },
];

// Common Cyrillic and Greek characters visually identical to Latin letters
const CONFUSABLE_MAP: Record<string, string> = {
  '\u0430': 'a', // Cyrillic small letter a
  '\u0441': 'c', // Cyrillic small letter es
  '\u0435': 'e', // Cyrillic small letter ie
  '\u043E': 'o', // Cyrillic small letter o
  '\u0440': 'p', // Cyrillic small letter er
  '\u0455': 's', // Cyrillic small letter dze
  '\u0456': 'i', // Cyrillic small letter byelorussian-ukrainian i
  '\u0458': 'j', // Cyrillic small letter je
  '\u0443': 'y', // Cyrillic small letter u
  '\u0445': 'x', // Cyrillic small letter ha
  '\u03BF': 'o', // Greek small letter omicron
  '\u03BD': 'v', // Greek small letter nu
  '\u03C1': 'p', // Greek small letter rho
};

/**
 * Standard Levenshtein distance between two strings
 */
export function calculateLevenshteinDistance(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Evaluates Homoglyphs, Punycode, Typosquatting, and Brand Combosquatting.
 */
export function analyzeHomoglyphsAndTypos(urlObj: URL, smsContext?: string): {
  analysis: HomoglyphAnalysis;
  indicators: HeuristicIndicator[];
} {
  const hostname = urlObj.hostname.toLowerCase();
  const apex = getApexDomain(hostname);
  const apexNameOnly = apex.split('.')[0];
  const fullPathAndHost = (urlObj.hostname + urlObj.pathname + urlObj.search).toLowerCase();
  const contextLower = (smsContext || '').toLowerCase();

  // Punycode detection and Unicode resolution
  const isPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
  let decodedPunycode: string | undefined;
  try {
    const unicodeHost = url.domainToUnicode(hostname);
    if (unicodeHost !== hostname) {
      decodedPunycode = unicodeHost;
    }
  } catch {
    // Ignore decode error
  }

  // The string to check for confusables (either raw hostname or decoded punycode)
  const targetCheckStr = decodedPunycode || hostname;

  // Mixed scripts / Confusables detection
  const confusableCharacters: string[] = [];
  let normalizedFromConfusables = targetCheckStr;

  for (const [confusable, latin] of Object.entries(CONFUSABLE_MAP)) {
    if (targetCheckStr.includes(confusable)) {
      confusableCharacters.push(`${confusable} (mimicking '${latin}')`);
      normalizedFromConfusables = normalizedFromConfusables.replaceAll(confusable, latin);
    }
  }
  const hasMixedScript = confusableCharacters.length > 0;

  // Leetspeak normalization
  const normalizedLeet = normalizedFromConfusables
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/5/g, 's')
    .replace(/vv/g, 'w')
    .replace(/rn/g, 'm');

  let isTyposquat = false;
  let matchedBrand: string | undefined;
  let officialDomain: string | undefined;
  let minLevenshtein = 999;
  let typosquatDetails: string | undefined;

  // Combosquatting keyword additions
  const phishingActionKeywords = ['login', 'verify', 'update', 'security', 'alert', 'support', 'billing', 'auth', 'account', 'signin', 'portal'];

  for (const item of TOP_TARGET_BRANDS) {
    const isActuallyOfficial = item.officialDomains.some(
      (dom) => apex === dom || hostname === dom || hostname.endsWith('.' + dom)
    );
    if (isActuallyOfficial) {
      continue;
    }

    // 1. Check if Homoglyph Confusables decoding exactly spells the brand!
    // (e.g. gооgle.com with Cyrillic 'о' decoded -> google)
    const normalizedApexOnly = normalizedFromConfusables.split('.')[0].replace(/^xn--/, '');
    if (hasMixedScript && normalizedApexOnly === item.canonicalSlug) {
      isTyposquat = true;
      matchedBrand = item.brand;
      officialDomain = item.officialDomains[0];
      typosquatDetails = `Visual Homoglyph Attack: Host uses Cyrillic/Greek characters that visually disguise "${item.brand}" (spoofs authentic ${item.officialDomains[0]}).`;
      minLevenshtein = 0;
      break;
    }

    // 2. Levenshtein Distance Check on Apex root
    const dist = calculateLevenshteinDistance(apexNameOnly, item.canonicalSlug);
    if (dist > 0 && dist <= 2 && apexNameOnly.length >= 4 && item.canonicalSlug.length >= 4) {
      if (dist < minLevenshtein) {
        minLevenshtein = dist;
        isTyposquat = true;
        matchedBrand = item.brand;
        officialDomain = item.officialDomains[0];
        typosquatDetails = `Domain "${apex}" is ${dist} edit(s) away from official brand "${item.canonicalSlug}" (mimics ${item.officialDomains[0]}).`;
      }
    }

    // 3. Leetspeak substitution check (e.g. paypa1 vs paypal)
    if (!isTyposquat && normalizedLeet.includes(item.canonicalSlug) && !hostname.includes(item.canonicalSlug)) {
      isTyposquat = true;
      matchedBrand = item.brand;
      officialDomain = item.officialDomains[0];
      typosquatDetails = `Leetspeak character substitution imitating ${item.brand} (mimics ${item.officialDomains[0]}).`;
    }

    // 4. Combosquatting check (e.g. paypal-security-update.com or chase-login-portal.xyz)
    if (!isTyposquat && apexNameOnly.includes(item.canonicalSlug)) {
      const hasActionKeyword = phishingActionKeywords.some((kw) => fullPathAndHost.includes(kw) || apexNameOnly.includes(kw));
      if (hasActionKeyword) {
        isTyposquat = true;
        matchedBrand = item.brand;
        officialDomain = item.officialDomains[0];
        typosquatDetails = `Combosquatting: Domain embeds "${item.brand}" alongside action keywords but is registered under untrusted "${apex}".`;
      }
    }

    // 5. SMS / Message pretext impersonation check
    if (!isTyposquat && contextLower) {
      const mentionsBrand = item.keywords.some((kw) => contextLower.includes(kw));
      if (mentionsBrand) {
        isTyposquat = true;
        matchedBrand = item.brand;
        officialDomain = item.officialDomains[0];
        typosquatDetails = `Message pretext claims to originate from ${item.brand}, but routes user to unrelated host "${apex}".`;
      }
    }
  }

  const analysis: HomoglyphAnalysis = {
    isPunycode,
    decodedPunycode,
    hasMixedScript,
    confusableCharacters,
    isTyposquat,
    matchedBrand,
    officialDomain,
    levenshteinDistance: minLevenshtein < 999 ? minLevenshtein : undefined,
    typosquatDetails,
  };

  const indicators: HeuristicIndicator[] = [];

  // Punycode Indicator
  if (isPunycode) {
    indicators.push({
      id: 'homoglyph-punycode',
      module: 'HOMOGLYPH',
      title: 'Internationalized Domain Name (Punycode xn--)',
      description: decodedPunycode
        ? `Host utilizes Punycode encoding (decodes to "${decodedPunycode}"). Historically exploited to display non-Latin letters that visually duplicate familiar ASCII domains.`
        : 'Host utilizes Punycode encoding, a mechanism historically exploited to display non-Latin letters that visually duplicate familiar ASCII domains.',
      severity: 'CRITICAL',
      points: 35,
      passed: false,
    });
  }

  // Mixed Script Indicator
  if (hasMixedScript) {
    indicators.push({
      id: 'homoglyph-mixed-script',
      module: 'HOMOGLYPH',
      title: 'Homoglyph Visual Mimicry (Mixed Scripts)',
      description: `Detected confusable non-ASCII characters: ${confusableCharacters.join(', ')}. Used to deceive human eyes into reading a legitimate brand name.`,
      severity: 'CRITICAL',
      points: 45,
      passed: false,
    });
  }

  // Typosquatting / Combosquatting Indicator
  if (isTyposquat && matchedBrand) {
    indicators.push({
      id: 'homoglyph-typosquat',
      module: 'HOMOGLYPH',
      title: `Typosquatting & Brand Spoof (${matchedBrand})`,
      description: typosquatDetails || `Unauthorized impersonation of ${matchedBrand}. Target apex "${apex}" is not registered to official entity ${officialDomain}.`,
      severity: 'CRITICAL',
      points: 45,
      passed: false,
    });
  } else {
    indicators.push({
      id: 'homoglyph-typosquat',
      module: 'HOMOGLYPH',
      title: 'No Homoglyph or Brand Typosquat Detected',
      description: 'Hostname does not trigger typosquatting, Levenshtein distance flags, or known brand mimicry patterns.',
      severity: 'INFO',
      points: 0,
      passed: true,
    });
  }

  return { analysis, indicators };
}
