import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import {
  extractUrlFromInput,
  getApexDomain,
  detectBrandImpersonation,
  inspectDns,
  inspectRdap,
  inspectSsl,
  traceRedirects,
  evaluateIndicators,
} from './src/services/scanner.js';
import { analyzeThreatWithGemini } from './src/services/aiAnalyzer.js';
import type { ScanResult } from './src/types/scanner.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  app.use(express.json({ limit: '2mb' }));

  // Quick Samples for instant 1-click testing
  app.get('/api/quick-samples', (_req, res) => {
    res.json([
      {
        id: 'sample-usps-smishing',
        category: 'SMS Package Scam (Smishing)',
        riskExpectation: 'HIGH_RISK',
        label: 'USPS Delivery Fee SMS',
        rawText: 'USPS Notice: Your parcel #94001000 is on hold due to missing house number. Confirm address and pay $0.35 redelivery fee at https://usps-redelivery-notice.top/track within 24h to avoid return.',
        url: 'https://usps-redelivery-notice.top/track',
      },
      {
        id: 'sample-netflix-phish',
        category: 'Streaming Account Suspension',
        riskExpectation: 'HIGH_RISK',
        label: 'Netflix Account Hold',
        rawText: 'Netflix: Your membership payment failed. Update your card now to continue streaming: https://netflix-update-billing-profile.xyz/login',
        url: 'https://netflix-update-billing-profile.xyz/login',
      },
      {
        id: 'sample-bofa-phish',
        category: 'Urgent Banking Alert',
        riskExpectation: 'HIGH_RISK',
        label: 'Bank of America Security Alert',
        rawText: 'BOA Alert: An unauthorized withdrawal of $450.00 was requested. If this was not you, verify immediately: https://bankofamerica.com.login-verify-alert.click/auth',
        url: 'https://bankofamerica.com.login-verify-alert.click/auth',
      },
      {
        id: 'sample-apple-smishing',
        category: 'iCloud Find My Alert',
        riskExpectation: 'HIGH_RISK',
        label: 'Apple iCloud Lost Device',
        rawText: 'Apple Support: Your lost iPhone 15 Pro was located online at 04:12 AM. View location & passcode lock: https://icloud-find-device-security.club/map',
        url: 'https://icloud-find-device-security.club/map',
      },
      {
        id: 'sample-legit-wiki',
        category: 'Legitimate Resource',
        riskExpectation: 'SAFE',
        label: 'Wikipedia Security Guide',
        rawText: 'Read educational guide on social engineering: https://en.wikipedia.org/wiki/Phishing',
        url: 'https://en.wikipedia.org/wiki/Phishing',
      },
      {
        id: 'sample-legit-github',
        category: 'Legitimate Developer Platform',
        riskExpectation: 'SAFE',
        label: 'GitHub Documentation',
        rawText: 'Official GitHub documentation: https://docs.github.com/en/authentication',
        url: 'https://docs.github.com/en/authentication',
      },
    ]);
  });

  // Main OSINT & Phishing Scan Endpoint
  app.post('/api/scan', async (req, res) => {
    const startTime = Date.now();
    try {
      const { input } = req.body;
      if (!input || typeof input !== 'string') {
        res.status(400).json({ error: 'Please provide a valid URL or SMS message text to scan.' });
        return;
      }

      const { url: extractedUrl, context: smsMessageContext } = extractUrlFromInput(input);
      let parsedUrl: URL;
      try {
        if (!extractedUrl || !extractedUrl.includes('.')) {
          throw new Error('No domain');
        }
        parsedUrl = new URL(extractedUrl);
        if (!parsedUrl.hostname || !parsedUrl.hostname.includes('.')) {
          throw new Error('Invalid host');
        }
      } catch {
        res.status(400).json({
          error: 'Could not detect a valid web address or domain name in your input. Please provide a link (e.g. example.com or https://...) or paste a text message containing one.',
        });
        return;
      }

      const targetDomain = parsedUrl.hostname;
      const apexDomain = getApexDomain(targetDomain);

      // Concurrent OSINT Inspections
      const [dnsResult, sslResult, rdapResult, redirectResult] = await Promise.all([
        inspectDns(targetDomain),
        inspectSsl(targetDomain, parsedUrl.port ? Number(parsedUrl.port) : 443),
        inspectRdap(apexDomain),
        traceRedirects(extractedUrl, 5),
      ]);

      // Brand impersonation check (evaluating URL and message context)
      const brandCheck = detectBrandImpersonation(parsedUrl, smsMessageContext);

      // Evaluate heuristic indicators
      let finalUrlObj = parsedUrl;
      try {
        finalUrlObj = new URL(redirectResult.finalUrl);
      } catch {
        // Fallback to initial
      }

      const { indicators, computedScore } = evaluateIndicators({
        urlObj: parsedUrl,
        finalUrlObj,
        rawInput: input,
        dns: dnsResult,
        ssl: sslResult,
        rdap: rdapResult,
        brandCheck,
        hopsCount: redirectResult.hops.length,
      });

      // Gemini AI Threat Synthesis
      const aiAnalysis = await analyzeThreatWithGemini({
        url: extractedUrl,
        domain: targetDomain,
        apexDomain,
        smsContext: smsMessageContext,
        baselineScore: computedScore,
        dns: dnsResult,
        ssl: sslResult,
        rdap: rdapResult,
        brandCheck,
        indicators,
      });

      const scanResult: ScanResult = {
        id: `scan-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        timestamp: new Date().toISOString(),
        originalInput: input,
        extractedUrl,
        smsMessageContext,
        normalizedUrl: parsedUrl.toString(),
        targetDomain,
        apexDomain,
        finalUrl: redirectResult.finalUrl,
        riskLevel: aiAnalysis.verdict,
        riskScore: aiAnalysis.riskScore,
        aiAnalysis,
        redirects: redirectResult.hops,
        dns: dnsResult,
        ssl: sslResult,
        rdap: rdapResult,
        brandCheck,
        indicators,
        executionTimeMs: Date.now() - startTime,
      };

      res.json(scanResult);
    } catch (err: unknown) {
      console.error('Scan processing error:', err);
      res.status(500).json({
        error: err instanceof Error ? err.message : 'An unexpected error occurred while analyzing the link.',
      });
    }
  });

  // Health check
  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'operational',
      engine: 'SentinelLink OSINT Micro-Service',
      hasGeminiKey: Boolean(process.env.GEMINI_API_KEY),
      timestamp: new Date().toISOString(),
    });
  });

  // Vite integration: middleware mode in dev, static files in production
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  process.on('uncaughtException', (err) => {
    console.error('Unhandled process exception:', err);
  });

  process.on('unhandledRejection', (reason) => {
    console.error('Unhandled promise rejection:', reason);
  });

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SentinelLink security micro-service running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
