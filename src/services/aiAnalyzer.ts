import { GoogleGenAI, Type } from '@google/genai';
import type {
  AiThreatAnalysis,
  DnsInfo,
  SslInfo,
  RdapInfo,
  BrandImpersonationCheck,
  HeuristicIndicator,
  RiskLevel,
} from '../types/scanner.js';

let aiInstance: GoogleGenAI | null = null;

function getAiClient(): GoogleGenAI {
  if (!aiInstance) {
    aiInstance = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return aiInstance;
}

export async function analyzeThreatWithGemini(params: {
  url: string;
  domain: string;
  apexDomain: string;
  smsContext?: string;
  baselineScore: number;
  dns: DnsInfo;
  ssl: SslInfo;
  rdap: RdapInfo;
  brandCheck: BrandImpersonationCheck;
  indicators: HeuristicIndicator[];
}): Promise<AiThreatAnalysis> {
  const {
    url,
    domain,
    apexDomain,
    smsContext,
    baselineScore,
    dns,
    ssl,
    rdap,
    brandCheck,
    indicators,
  } = params;

  // Fallback function in case Gemini is unreachable
  const generateFallback = (): AiThreatAnalysis => {
    let verdict: RiskLevel = 'SAFE';
    if (baselineScore >= 60) verdict = 'HIGH_RISK';
    else if (baselineScore >= 35) verdict = 'SUSPICIOUS';
    else if (baselineScore >= 15) verdict = 'LOW_RISK';

    const failedAlarms = indicators.filter((i) => !i.passed);
    const actions: string[] = [];

    if (verdict === 'HIGH_RISK') {
      actions.push('Do NOT click or open this link on your phone or computer.');
      actions.push('Do NOT provide passwords, one-time SMS verification codes, or credit card details.');
      actions.push('Delete the text message or email and block the sender phone number / email.');
      if (brandCheck.targetedBrand) {
        actions.push(`If you have an account with ${brandCheck.targetedBrand}, visit their official website directly (${brandCheck.officialDomain}) by typing it into your browser.`);
      }
    } else if (verdict === 'SUSPICIOUS') {
      actions.push('Exercise strong caution before visiting or submitting any personal information.');
      actions.push('Verify the sender through an official support channel or by checking your account directly in the official app.');
    } else {
      actions.push('No obvious brand spoofing or known high-risk infrastructure was detected.');
      actions.push('Always ensure the address bar displays the exact spelling of the domain you intend to visit.');
    }

    return {
      verdict,
      riskScore: baselineScore,
      title:
        verdict === 'HIGH_RISK'
          ? brandCheck.isImpersonating
            ? `Critical Warning: High-Risk ${brandCheck.targetedBrand || 'Brand'} Impersonation Link`
            : 'Critical Threat: High-Risk Deceptive Domain'
          : verdict === 'SUSPICIOUS'
          ? 'Caution Advised: Unverified or Recently Created Link'
          : 'Low Risk: Established Domain Infrastructure',
      plainEnglishSummary:
        verdict === 'HIGH_RISK'
          ? `This link directs to an unauthorized domain (${apexDomain}) that displays high-risk phishing indicators. ${
              brandCheck.isImpersonating
                ? `It appears engineered to deceive you into believing it belongs to ${brandCheck.targetedBrand}.`
                : 'It is hosted on disposable or deceptive infrastructure.'
            }`
          : verdict === 'SUSPICIOUS'
          ? `This link has some anomalies such as recent domain registration or unusual redirect behavior. It cannot be verified as completely safe.`
          : `The link points to an established domain with standard public DNS records and active SSL encryption.`,
      dangerExplanation:
        verdict === 'HIGH_RISK'
          ? 'Attackers frequently use these pages to harvest usernames, passwords, credit card numbers, or trick you into installing malicious configuration profiles.'
          : 'Proceed only if you specifically requested or expected this message from a trusted sender.',
      attackVector: brandCheck.isImpersonating
        ? 'Brand Impersonation / Credential Harvester (Smishing/Phishing)'
        : baselineScore > 50
        ? 'Suspicious Malicious Link'
        : 'Legitimate or Low-Risk Link',
      recommendedActions: actions,
      technicalHighlights: failedAlarms.map((a) => `${a.title}: ${a.description}`).slice(0, 4),
    };
  };

  // If no Gemini API key configured, use high-precision heuristic synthesis directly
  if (!process.env.GEMINI_API_KEY) {
    return generateFallback();
  }

  try {
    const ai = getAiClient();

    const telemetryReport = `
TARGET URL: ${url}
APEX DOMAIN: ${apexDomain}
FULL HOSTNAME: ${domain}
SMS/EMAIL CONTEXT TEXT: ${smsContext || 'None provided'}
DOMAIN AGE: ${rdap.domainAgeDays !== undefined ? `${rdap.domainAgeDays} days (Registered: ${rdap.registrationDate})` : 'Unknown / Hidden'}
REGISTRAR: ${rdap.registrar || 'Unknown'}
SSL ISSUER: ${ssl.issuerOrg || 'None'} (Valid: ${ssl.valid}, Days remaining: ${ssl.daysRemaining ?? 'N/A'})
DNS RESOLVED IPS: ${dns.resolvedIps.join(', ') || 'None'}
MX RECORDS: ${dns.hasMxRecords ? dns.mxRecords.map((m) => m.exchange).join(', ') : 'None'}
BRAND IMPERSONATION TRIGGERED: ${brandCheck.isImpersonating ? `YES, imitating ${brandCheck.targetedBrand} (official is ${brandCheck.officialDomain})` : 'NO'}
FAILED HEURISTIC INDICATORS:
${indicators.filter((i) => !i.passed).map((i) => `- [${i.severity}] ${i.title}: ${i.description}`).join('\n') || 'None'}
BASELINE AUTOMATED SCORE: ${baselineScore}/100
`;

    const prompt = `You are an elite cyber threat analyst and OSINT security advisor for non-technical users.
Analyze the following URL and backend OSINT telemetry to determine whether it is a malicious phishing scam, smishing link, or legitimate.

Write a clear, non-technical explanation that anyone (e.g. grandparents, teenagers, non-tech workers) can immediately understand and act upon without panic, while providing precise technical reasoning.

Here is the telemetry data:
${telemetryReport}

Return a structured JSON evaluation adhering to the requested schema.`;

    const generatePromise = ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            verdict: {
              type: Type.STRING,
              description: 'MUST be one of: HIGH_RISK, SUSPICIOUS, LOW_RISK, SAFE',
            },
            riskScore: {
              type: Type.INTEGER,
              description: 'Integer from 0 (completely safe) to 100 (critical danger)',
            },
            title: {
              type: Type.STRING,
              description: 'Scannable headline summary (e.g., "Critical Alert: Deceptive USPS Smishing Scheme")',
            },
            plainEnglishSummary: {
              type: Type.STRING,
              description: '2 to 3 sentences in plain English explaining what this link is and who it is trying to trick.',
            },
            dangerExplanation: {
              type: Type.STRING,
              description: 'Clear statement of what happens if someone clicks or submits their data on this page.',
            },
            attackVector: {
              type: Type.STRING,
              description: 'Specific threat type, e.g. "SMS Package Delivery Smishing (Postage Fee Pretext)", "Banking Credential Harvester", "Account Suspension Phish", or "Legitimate Service Link"',
            },
            recommendedActions: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: '3-5 concrete, step-by-step action items for the user (e.g., "Do not click", "Block sender", "Contact bank if submitted")',
            },
            technicalHighlights: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: '3-4 key technical findings supporting this verdict (e.g., "Domain registered 3 days ago", "Let\'s Encrypt certificate on supposed bank portal")',
            },
          },
          required: [
            'verdict',
            'riskScore',
            'title',
            'plainEnglishSummary',
            'dangerExplanation',
            'attackVector',
            'recommendedActions',
            'technicalHighlights',
          ],
        },
      },
    });

    const response = await Promise.race([
      generatePromise,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('AI generation timeout')), 4500)),
    ]);

    const parsed = JSON.parse(response.text || '{}');
    
    // Validate verdict
    let verdict: RiskLevel = 'SAFE';
    if (parsed.verdict === 'HIGH_RISK' || parsed.verdict === 'SUSPICIOUS' || parsed.verdict === 'LOW_RISK' || parsed.verdict === 'SAFE') {
      verdict = parsed.verdict;
    } else {
      verdict = parsed.riskScore >= 55 ? 'HIGH_RISK' : parsed.riskScore >= 30 ? 'SUSPICIOUS' : 'SAFE';
    }

    let finalScore = typeof parsed.riskScore === 'number' ? Math.min(100, Math.max(0, parsed.riskScore)) : baselineScore;

    // Hard safety guard: Critical telemetry indicators (brand spoof, homograph, brand new high-abuse domain) must never produce false negative
    if (brandCheck.isImpersonating || baselineScore >= 55) {
      verdict = 'HIGH_RISK';
      finalScore = Math.max(finalScore, baselineScore, 75);
    } else if (baselineScore >= 30 && (verdict === 'SAFE' || verdict === 'LOW_RISK')) {
      verdict = 'SUSPICIOUS';
      finalScore = Math.max(finalScore, baselineScore);
    }

    const title = brandCheck.isImpersonating
      ? `Critical Phishing Alert: Fake ${brandCheck.targetedBrand} Link`
      : parsed.title || 'Security Analysis Complete';

    return {
      verdict,
      riskScore: finalScore,
      title,
      plainEnglishSummary: parsed.plainEnglishSummary || '',
      dangerExplanation: parsed.dangerExplanation || '',
      attackVector: brandCheck.isImpersonating
        ? `Brand Impersonation / Credential Harvester (${brandCheck.targetedBrand})`
        : parsed.attackVector || 'Phishing / Deceptive Link',
      recommendedActions: Array.isArray(parsed.recommendedActions) && parsed.recommendedActions.length > 0
        ? parsed.recommendedActions
        : generateFallback().recommendedActions,
      technicalHighlights: Array.isArray(parsed.technicalHighlights) && parsed.technicalHighlights.length > 0
        ? parsed.technicalHighlights
        : indicators.filter((i) => !i.passed).map((i) => `${i.title}: ${i.description}`).slice(0, 4),
    };
  } catch (err) {
    console.error('Gemini analysis error, falling back to heuristic engine:', err);
    return generateFallback();
  }
}
