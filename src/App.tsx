import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar.js';
import { ScannerForm } from './components/ScannerForm.js';
import { VerdictHero } from './components/VerdictHero.js';
import { ActionChecklist } from './components/ActionChecklist.js';
import { OsintInspector } from './components/OsintInspector.js';
import { SmishingGuide } from './components/SmishingGuide.js';
import { ScanHistory } from './components/ScanHistory.js';
import { ReportModal } from './components/ReportModal.js';
import type { ScanResult } from './types/scanner.js';
import { Shield, Sparkles, AlertTriangle, ShieldCheck, ArrowRight } from 'lucide-react';

const STORAGE_KEY = 'sentinellink_scan_history_v1';

export default function App() {
  const [activeTab, setActiveTab] = useState<'scanner' | 'guide' | 'history'>('scanner');
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);
  const [scanInput, setScanInput] = useState<string>('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [quickSamples, setQuickSamples] = useState<any[]>([]);

  // Load history from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        setHistory(JSON.parse(stored));
      }
    } catch {
      // Ignore localStorage read errors
    }
  }, []);

  // Fetch quick test samples from backend
  useEffect(() => {
    fetch('/api/quick-samples')
      .then((res) => (res.ok ? res.json() : []))
      .then((data) => {
        if (Array.isArray(data) && data.length > 0) {
          setQuickSamples(data);
        }
      })
      .catch(() => {
        // Fallback samples
        setQuickSamples([
          {
            id: 'sample-usps',
            category: 'SMS Package Scam',
            riskExpectation: 'HIGH_RISK',
            label: 'USPS Delivery Fee SMS',
            rawText:
              'USPS Notice: Your parcel #94001000 is on hold due to missing address. Confirm address and pay $0.35 redelivery fee at https://usps-redelivery-notice.top/track within 24h to avoid return.',
            url: 'https://usps-redelivery-notice.top/track',
          },
          {
            id: 'sample-netflix',
            category: 'Streaming Phish',
            riskExpectation: 'HIGH_RISK',
            label: 'Netflix Account Hold',
            rawText:
              'Netflix: Your membership payment failed. Update card to continue streaming: https://netflix-update-billing-profile.xyz/login',
            url: 'https://netflix-update-billing-profile.xyz/login',
          },
          {
            id: 'sample-wiki',
            category: 'Legitimate Service',
            riskExpectation: 'SAFE',
            label: 'Wikipedia Article',
            rawText: 'Learn about phishing on Wikipedia: https://en.wikipedia.org/wiki/Phishing',
            url: 'https://en.wikipedia.org/wiki/Phishing',
          },
        ]);
      });
  }, []);

  // Execute scan against backend micro-service
  const handleScan = async (input: string) => {
    setScanInput(input);
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || `HTTP scan request failed with status ${response.status}`);
      }

      const result: ScanResult = await response.json();
      setCurrentResult(result);
      setActiveTab('scanner');

      // Update history
      setHistory((prev) => {
        const filtered = prev.filter((item) => item.extractedUrl !== result.extractedUrl);
        const updated = [result, ...filtered].slice(0, 20);
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
        } catch {
          // Ignore storage quota
        }
        return updated;
      });

      // Smooth scroll to results
      setTimeout(() => {
        const element = document.getElementById('scan-results-anchor');
        if (element) {
          element.scrollIntoView({ behavior: 'smooth' });
        }
      }, 100);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'An unexpected error occurred during scan.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      // Ignore
    }
  };

  const handleRemoveHistoryItem = (id: string) => {
    setHistory((prev) => {
      const updated = prev.filter((item) => item.id !== id);
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
      } catch {
        // Ignore
      }
      return updated;
    });
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* 3-Zone Top Bar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onQuickSampleClick={() => {
          setActiveTab('scanner');
          if (quickSamples.length > 0) {
            handleScan(quickSamples[0].rawText);
          }
        }}
      />

      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12">
        {/* Hero Introduction Section */}
        <div className="mb-10 text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 rounded-full border border-slate-800 bg-slate-900/80 px-4 py-1.5 text-xs text-slate-300 mb-4 backdrop-blur-sm">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
            <span>Automated OSINT & Smishing Verification Engine</span>
            <span className="text-slate-600">/</span>
            <span className="text-amber-400 font-mono font-medium">Domain Age · SSL · RDAP</span>
          </div>

          <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white text-balance leading-tight sm:leading-tight">
            Verify Suspicious Links <br className="hidden sm:inline" />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-amber-300 via-amber-400 to-orange-400">
              Before You Click
            </span>
          </h1>

          <p className="mt-4 text-sm sm:text-base text-slate-400 text-balance leading-relaxed">
            People constantly receive suspicious links via SMS or email and lack the technical skills to verify them safely. SentinelLink inspects domain age, SSL integrity, redirection chains, and deceptive brand spoofing to give you a definitive Safe or High Risk verdict.
          </p>
        </div>

        {/* Tab Viewport */}
        {activeTab === 'scanner' && (
          <div className="space-y-8">
            {/* Input Console */}
            <ScannerForm
              onScan={handleScan}
              isLoading={isLoading}
              samples={quickSamples}
              inputValue={scanInput}
              activeSampleModalOpen={false}
              onCloseSampleModal={() => {}}
            />

            {/* Error Message Box */}
            {errorMsg && (
              <div className="rounded-xl border border-rose-900/80 bg-rose-950/40 p-4 text-xs sm:text-sm text-rose-300 flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold block mb-0.5">Verification Error</span>
                  <span>{errorMsg}</span>
                </div>
              </div>
            )}

            {/* Results Anchor */}
            <div id="scan-results-anchor" />

            {/* Active Scan Results Display */}
            {currentResult && (
              <div className="space-y-8 animate-in fade-in duration-500">
                {/* 1. Verdict Banner & Risk Score */}
                <VerdictHero
                  result={currentResult}
                  onOpenActionPlan={() => {
                    const el = document.getElementById('action-plan-section');
                    if (el) el.scrollIntoView({ behavior: 'smooth' });
                  }}
                  onOpenExportModal={() => setIsExportModalOpen(true)}
                />

                {/* 2. Action Plan Section */}
                <div id="action-plan-section">
                  <ActionChecklist result={currentResult} />
                </div>

                {/* 3. Deep-Dive OSINT Telemetry Suite */}
                <OsintInspector result={currentResult} />
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Smishing Educational Guide */}
        {activeTab === 'guide' && (
          <SmishingGuide
            onTestSample={(sampleLink) => {
              setActiveTab('scanner');
              handleScan(sampleLink);
            }}
          />
        )}

        {/* Tab 3: History Vault */}
        {activeTab === 'history' && (
          <ScanHistory
            history={history}
            onSelectScan={(scan) => {
              setCurrentResult(scan);
              setScanInput(scan.originalInput || scan.extractedUrl);
              setActiveTab('scanner');
              setTimeout(() => {
                const el = document.getElementById('scan-results-anchor');
                if (el) el.scrollIntoView({ behavior: 'smooth' });
              }, 100);
            }}
            onClearHistory={handleClearHistory}
            onRemoveScan={handleRemoveHistoryItem}
          />
        )}
      </main>

      {/* Export Report Modal */}
      {isExportModalOpen && (
        <ReportModal
          result={currentResult}
          onClose={() => setIsExportModalOpen(false)}
        />
      )}

      {/* Footer (Anti-Slop Restraint: quiet copyright & disclaimer) */}
      <footer className="mt-16 border-t border-slate-900 bg-slate-950 py-8 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-400">SentinelLink</span>
            <span>·</span>
            <span>Automated OSINT Phishing Defense</span>
          </div>
          <p className="text-center sm:text-right text-[11px] text-slate-600 max-w-md">
            Heuristic security analysis engine for proactive verification. Never input credentials or personal data on unverified websites.
          </p>
        </div>
      </footer>
    </div>
  );
}
