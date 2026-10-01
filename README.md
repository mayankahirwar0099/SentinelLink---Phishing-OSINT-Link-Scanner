### Overview & Purpose

People frequently receive suspicious links via SMS or email and lack an easy, safe way to check them before clicking. SentinelLink inspects domain registration age, SSL certificates, DNS records, and brand spoofing patterns to give you a clear Safe or High Risk verdict. It translates complex security telemetry into plain English with practical steps anyone can follow.

### Key Features

- **Smart Message & Link Extraction:** Paste a raw web address or an entire SMS text message; SentinelLink automatically isolates the target link while stripping surrounding punctuation.
- **Real-Time OSINT Telemetry:** Queries RDAP domain registry age, verifies SSL/TLS certificate validity, and checks DNS A, AAAA, MX, and NS records.
- **Brand Impersonation & Homograph Checks:** Identifies lookalike domains, deceptive subdomain prefixes (e.g. `usps.com.fake-parcel.top`), and unauthorized brand claims.
- **Redirect Tracing & Unshortening:** Follows HTTP 301/302 hops to reveal the true final landing destination hidden behind shorteners like bit.ly or tinyurl.
- **Action Checklist & Exportable Reports:** Provides step-by-step guidance on what to do if you received or opened the link, plus a one-click text report to share with IT or family.

### Tech Stack

- **Frontend:** React 19, TypeScript, Tailwind CSS v4, Lucide React
- **Backend Server:** Node.js, Express, TSX, Vite (integrated middleware mode)
- **OSINT & Network Analysis:** Native Node.js `dns`, `tls`, `net`, RDAP domain registry API, HTTP redirect tracing
- **AI Threat Synthesis:** Google Gen AI SDK (`@google/genai` / Gemini 2.5 Flash) with automated offline heuristic fallback

### How to Run Locally

1. **Prerequisites:**
   Make sure you have **Node.js 18+** installed on your system.

2. **Install Dependencies:**
   ```bash
   npm install
   ```

3. **Configure Environment Variables (Optional):**
   Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
   Add your `GEMINI_API_KEY` if you want AI-assisted threat summaries. If left blank, the scanner will still run normally using its built-in heuristic analysis engine.

4. **Start the Development Server:**
   ```bash
   npm run dev
   ```

5. **Open in Your Browser:**
   Visit [http://localhost:3000](http://localhost:3000) to start inspecting links.
