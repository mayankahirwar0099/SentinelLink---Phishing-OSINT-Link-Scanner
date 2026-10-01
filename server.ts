import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import {
  extractUrlFromInput,
  performFullSecurityScan,
} from './src/services/scanner.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  app.use(express.json({ limit: '2mb' }));

  // Quick Samples for instant 1-click testing (Safe, Typosquat, High Risk)
  app.get('/api/quick-samples', (_req, res) => {
    res.json([
      {
        id: 'sample-safe-github',
        category: 'Safe Official Platform',
        riskExpectation: 'SAFE',
        label: 'GitHub Documentation (Safe)',
        rawText: 'Official GitHub documentation on authentication: https://docs.github.com/en/authentication',
        url: 'https://docs.github.com/en/authentication',
      },
      {
        id: 'sample-typosquat-paypal',
        category: 'Typosquatting & Homoglyph',
        riskExpectation: 'MALICIOUS',
        label: 'PayPa1 Account Spoof (Typosquat)',
        rawText: 'PayPal Alert: Unusual sign-in detected on your account. Verify identity at https://paypa1-security-verification.com/login immediately.',
        url: 'https://paypa1-security-verification.com/login',
      },
      {
        id: 'sample-highrisk-usps',
        category: 'SMS Package Scam (High Risk)',
        riskExpectation: 'MALICIOUS',
        label: 'USPS Redelivery Smish (High Risk)',
        rawText: 'USPS Notice: Your parcel #94001000 is on hold due to missing house number. Confirm address and pay $0.35 redelivery fee at https://usps-redelivery-notice.top/track within 24h to avoid return.',
        url: 'https://usps-redelivery-notice.top/track',
      },
      {
        id: 'sample-typosquat-chase',
        category: 'Banking Combosquatting',
        riskExpectation: 'MALICIOUS',
        label: 'Chase Security Phish (Combosquat)',
        rawText: 'CHASE Alert: A debit charge of $850.00 was requested. Cancel transfer at https://chase-security-verification.xyz/auth',
        url: 'https://chase-security-verification.xyz/auth',
      },
      {
        id: 'sample-safe-wiki',
        category: 'Safe Educational',
        riskExpectation: 'SAFE',
        label: 'Wikipedia Article (Safe)',
        rawText: 'Read about phishing defense: https://en.wikipedia.org/wiki/Phishing',
        url: 'https://en.wikipedia.org/wiki/Phishing',
      },
    ]);
  });

  // Main Deterministic OSINT & Heuristic Scan Endpoint
  app.post('/api/scan', async (req, res) => {
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

      // Execute modular analysis pipeline
      const scanResult = await performFullSecurityScan({
        rawInput: input,
        extractedUrl,
        smsContext: smsMessageContext,
        parsedUrl,
      });

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
      engine: 'SentinelLink Deterministic OSINT & Heuristic Engine',
      hasGemini: false,
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
    console.log(`SentinelLink OSINT heuristic engine running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
