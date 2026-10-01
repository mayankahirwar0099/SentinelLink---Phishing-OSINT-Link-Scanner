### Overview & Purpose

People frequently receive suspicious links via SMS or email and lack an easy, safe way to check them before clicking. SentinelLink inspects lexical URL structure, Shannon entropy, Punycode/Cyrillic homoglyphs, DOM password forms, domain registration age, and public threat feeds (URLhaus & PhishTank). It calculates a transparent composite risk score from 0 to 100 with clear defensive recommendations.

### Key Features

- **Shannon Entropy & Lexical Structure:** Computes algorithmic character randomness (identifying DGA domains), counts subdomain stacking, flags numeric IP hostnames, and monitors high-abuse top-level extensions (.zip, .top, etc.).
- **Homoglyph & Typosquatting Engine:** Detects Punycode (`xn--`), mixed Cyrillic/Greek character mimicry, and Levenshtein edit distance against top brands (PayPal, Chase, Google, Apple, Amazon, USPS, etc.).
- **DOM & Form Security Analysis:** Scans page HTML for unencrypted password fields (`<input type="password">` over HTTP), hidden iframes, and off-domain form actions.
- **OSINT & Network Telemetry:** Inspects RDAP domain age, verifies authoritative DNS A/AAAA, MX, and SPF anti-spoofing records, and audits SSL/TLS certificate validity.
- **Threat Intelligence Matching:** Queries community threat feeds (abuse.ch URLhaus & PhishTank) to flag verified malware distributors and active phishing campaigns.
- **Composite 3-Tier Risk Score (0-100):** Transparent scoring categorized into Low Risk / Safe (0-29), Suspicious (30-59), and Malicious / High Phishing Risk (60-100) with a detailed point breakdown.

### Tech Stack

- **Frontend:** React 19, TypeScript, Tailwind CSS v4, Lucide React
- **Backend Server:** Node.js, Express, TSX, Vite (integrated middleware mode)
- **Heuristic Engine:** Deterministic rule modules (Lexical, Homoglyph, DOM, Threat Intel, Scoring Engine)
- **OSINT & Network:** Native Node.js `dns`, `tls`, `net`, RDAP domain registry API, and HTTP redirect tracer

### How to Run Locally

1. **Prerequisites:**
   Make sure you have **Node.js 18+** installed on your system.

2. **Install Dependencies:**
   ```bash
   npm install
   ```

3. **Start the Development Server:**
   ```bash
   npm run dev
   ```

4. **Open in Your Browser:**
   Visit [http://localhost:3000](http://localhost:3000) to start inspecting links.
