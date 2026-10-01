import type {
  DeterministicVerdict,
  HeuristicIndicator,
  RiskLevel,
  LexicalAnalysis,
  HomoglyphAnalysis,
  DomFormAnalysis,
  ThreatIntelAnalysis,
  DnsInfo,
  SslInfo,
  RdapInfo,
} from '../../types/scanner.js';

export function calculateCompositeVerdict(params: {
  indicators: HeuristicIndicator[];
  targetDomain: string;
  apexDomain: string;
  lexical: LexicalAnalysis;
  homoglyph: HomoglyphAnalysis;
  dom: DomFormAnalysis;
  threatIntel: ThreatIntelAnalysis;
  dns: DnsInfo;
  ssl: SslInfo;
  rdap: RdapInfo;
}): DeterministicVerdict {
  const {
    indicators,
    targetDomain,
    apexDomain,
    lexical,
    homoglyph,
    dom,
    threatIntel,
    dns,
    ssl,
    rdap,
  } = params;

  // Sum points from all failed checks
  const flaggedIndicators = indicators.filter((ind) => !ind.passed);
  let rawScore = flaggedIndicators.reduce((acc, ind) => acc + (ind.points || 0), 0);

  // Critical safety triggers that mandate MALICIOUS threshold
  const hasCriticalMaliciousSignal =
    threatIntel.knownThreatListMatched ||
    dom.hasUnencryptedPasswordInput ||
    dom.fakeLoginFormDetected ||
    (homoglyph.isTyposquat && (lexical.isAbuseTld || rdap.isRecentlyRegistered || !ssl.valid));

  if (hasCriticalMaliciousSignal && rawScore < 65) {
    rawScore = Math.max(rawScore, 75);
  }

  // Suspicious threshold booster
  if ((homoglyph.isTyposquat || rdap.isBrandNew || lexical.isAbuseTld) && rawScore < 35) {
    rawScore = Math.max(rawScore, 40);
  }

  // Clamp composite score between 0 and 100
  const riskScore = Math.min(100, Math.max(0, rawScore));

  // Threshold categorization
  // 0 - 29: Low Risk / Safe
  // 30 - 59: Suspicious
  // 60 - 100: Malicious / High Phishing Risk
  let verdict: RiskLevel = 'SAFE';
  if (riskScore >= 60) {
    verdict = 'MALICIOUS';
  } else if (riskScore >= 30) {
    verdict = 'SUSPICIOUS';
  }

  // Determine attack vector label
  let attackVector = 'Standard Web Resource (Low Risk)';
  if (verdict === 'MALICIOUS') {
    if (threatIntel.knownThreatListMatched) {
      attackVector = 'Known Blacklisted Threat (Malware / Phishing Campaign)';
    } else if (homoglyph.isTyposquat) {
      attackVector = `Brand Impersonation / Credential Harvester (${homoglyph.matchedBrand || 'Brand Spoof'})`;
    } else if (dom.fakeLoginFormDetected || dom.hasPasswordInput) {
      attackVector = 'Credential Harvester (Fake Login Portal)';
    } else if (lexical.hasRawIp) {
      attackVector = 'Direct IP Phishing / C2 Infrastructure';
    } else {
      attackVector = 'High-Risk Deceptive Link';
    }
  } else if (verdict === 'SUSPICIOUS') {
    if (homoglyph.isTyposquat) {
      attackVector = `Potential Brand Typosquat (${homoglyph.matchedBrand || 'Brand Lookalike'})`;
    } else if (rdap.isRecentlyRegistered) {
      attackVector = 'Newly Registered / Unverified Domain';
    } else if (lexical.isAbuseTld) {
      attackVector = 'High-Abuse Top-Level Domain Extension';
    } else {
      attackVector = 'Suspicious Infrastructure Anomaly';
    }
  }

  // Construct clear, non-technical title and plain English summary
  let verdictTitle = 'Safe: Established Domain Infrastructure';
  let plainEnglishSummary = `This link points to an established domain (${apexDomain}) with valid security credentials and standard DNS telemetry. No brand spoofing or malicious indicators were found.`;
  let dangerExplanation = 'Proceed only if you intentionally requested this link from a recognized contact or organization.';

  if (verdict === 'MALICIOUS') {
    verdictTitle = homoglyph.isTyposquat
      ? `Malicious Threat: Fake ${homoglyph.matchedBrand} Phishing Scam`
      : 'Malicious Threat: High-Risk Phishing Link';

    plainEnglishSummary = `This link directs to an unauthorized domain (${apexDomain}) that shows multiple critical danger indicators. ${
      homoglyph.isTyposquat
        ? `It is engineered to deceive you into believing it belongs to ${homoglyph.matchedBrand}, but is not an official ${homoglyph.officialDomain} website.`
        : 'It matches signatures associated with fraudulent login pages or credential theft.'
    }`;

    dangerExplanation =
      'If you open this page or enter passwords, credit card numbers, or one-time verification codes, attackers will capture your information directly.';
  } else if (verdict === 'SUSPICIOUS') {
    verdictTitle = 'Caution Advised: Suspicious & Unverified Link';

    plainEnglishSummary = `This link contains anomalies such as an unusual domain extension (.${lexical.tld}), recent registration, or brand name similarities. It cannot be verified as completely authentic.`;

    dangerExplanation =
      'Avoid entering sensitive personal credentials or downloading attachments until you independently confirm the origin of the message.';
  }

  // Prescribed user action items
  const recommendedActions: string[] = [];
  if (verdict === 'MALICIOUS') {
    recommendedActions.push('Do NOT click, open, or interact with this link on your phone or computer.');
    recommendedActions.push('Do NOT provide passwords, verification codes, or credit card numbers.');
    recommendedActions.push('Delete the message immediately and block the sender phone number or email.');
    if (homoglyph.matchedBrand && homoglyph.officialDomain) {
      recommendedActions.push(
        `If you have an account with ${homoglyph.matchedBrand}, navigate to their official website directly (${homoglyph.officialDomain}) in a separate browser window.`
      );
    }
    if (dom.hasPasswordInput) {
      recommendedActions.push('If you already entered your password, change it immediately on the official service website.');
    }
  } else if (verdict === 'SUSPICIOUS') {
    recommendedActions.push('Exercise strong caution before visiting or submitting any information.');
    recommendedActions.push('Verify the sender through a known, trusted phone number or official mobile app.');
    recommendedActions.push('Inspect the address bar carefully to verify the exact spelling of the domain.');
  } else {
    recommendedActions.push('No obvious brand spoofing or known high-risk infrastructure was detected.');
    recommendedActions.push('Always ensure the address bar displays the exact spelling of the domain you intended to visit.');
  }

  return {
    verdict,
    riskScore,
    verdictTitle,
    plainEnglishSummary,
    dangerExplanation,
    attackVector,
    recommendedActions,
    flaggedPointsTotal: rawScore,
  };
}
