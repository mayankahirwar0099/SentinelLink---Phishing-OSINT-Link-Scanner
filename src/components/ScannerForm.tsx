import React, { useState, useEffect } from 'react';
import { Search, Clipboard, X, ArrowRight, AlertTriangle, ShieldCheck, Mail, Smartphone, Globe, Sparkles } from 'lucide-react';
import { extractUrlFromInput } from '../utils/urlHelper.js';

interface QuickSample {
  id: string;
  category: string;
  riskExpectation: 'HIGH_RISK' | 'SAFE';
  label: string;
  rawText: string;
  url: string;
}

interface ScannerFormProps {
  onScan: (input: string) => Promise<void>;
  isLoading: boolean;
  activeSampleModalOpen: boolean;
  onCloseSampleModal: () => void;
  samples: QuickSample[];
  inputValue?: string;
}

export const ScannerForm: React.FC<ScannerFormProps> = ({
  onScan,
  isLoading,
  samples,
  inputValue,
}) => {
  const [input, setInput] = useState(inputValue || '');
  const [extractedPreview, setExtractedPreview] = useState<{ url: string; context?: string } | null>(null);
  const [loadingPhase, setLoadingPhase] = useState(0);

  useEffect(() => {
    if (inputValue !== undefined && inputValue !== input) {
      setInput(inputValue);
    }
  }, [inputValue]);

  const loadingSteps = [
    'Parsing URL syntax & homograph encoding...',
    'Performing DNS & Mail Exchange (MX) lookups...',
    'Inspecting SSL/TLS certificate validity & issuer...',
    'Querying RDAP for domain registration age...',
    'Tracing redirection hops & unshortening destination...',
    'Evaluating threat heuristics & brand spoof signatures...',
    'Synthesizing plain-English threat verdict with Gemini AI...',
  ];

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isLoading) {
      setLoadingPhase(0);
      interval = setInterval(() => {
        setLoadingPhase((prev) => (prev + 1) % loadingSteps.length);
      }, 700);
    }
    return () => clearInterval(interval);
  }, [isLoading]);

  useEffect(() => {
    if (input.trim()) {
      const extracted = extractUrlFromInput(input);
      setExtractedPreview(extracted);
    } else {
      setExtractedPreview(null);
    }
  }, [input]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;
    onScan(input.trim());
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setInput(text);
      }
    } catch {
      // Clipboard permissions denied or unavailable
    }
  };

  const handleSelectSample = (sampleText: string) => {
    setInput(sampleText);
    onScan(sampleText);
  };

  return (
    <div className="w-full">
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-2xl backdrop-blur-sm sm:p-7">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex items-center justify-between">
            <label htmlFor="url-input" className="text-sm font-semibold text-slate-200">
              Submit Link or Message for Security Verification
            </label>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handlePaste}
                className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-amber-300 transition-colors"
              >
                <Clipboard className="h-3.5 w-3.5" />
                <span>Paste from Clipboard</span>
              </button>
              {input && (
                <button
                  type="button"
                  onClick={() => setInput('')}
                  className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 transition-colors"
                >
                  <X className="h-3.5 w-3.5" />
                  <span>Clear</span>
                </button>
              )}
            </div>
          </div>

          <div className="relative">
            <textarea
              id="url-input"
              rows={3}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Paste suspicious URL or full SMS/email text (e.g. 'USPS: Your package 94001000 is on hold due to missing address. Update now at https://usps-redelivery.xyz/track')"
              className="w-full resize-none rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-slate-100 placeholder-slate-500 focus:border-amber-500 focus:outline-none focus:ring-1 focus:ring-amber-500 font-mono text-sm leading-relaxed"
              disabled={isLoading}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
                  handleSubmit(e);
                }
              }}
            />
          </div>

          {/* Real-time Extractor Preview if full text pasted */}
          {extractedPreview && extractedPreview.context && (
            <div className="rounded-lg border border-slate-800/80 bg-slate-950/60 p-3 text-xs text-slate-400">
              <div className="flex items-center gap-1.5 font-medium text-amber-400 mb-1">
                <Sparkles className="h-3.5 w-3.5" />
                <span>Detected Message Pretext & Target URL</span>
              </div>
              <div className="font-mono text-slate-300 break-all bg-slate-900/80 px-2 py-1.5 rounded border border-slate-800 mb-1">
                Target Link: <span className="text-amber-200 font-semibold">{extractedPreview.url}</span>
              </div>
              <p className="line-clamp-2 text-slate-400 italic">
                "{extractedPreview.context}"
              </p>
            </div>
          )}

          {/* Action Row */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-1">
            <div className="text-xs text-slate-400 flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-full bg-emerald-500" />
              <span>Real-time OSINT · RDAP Age · TLS Audit · Gemini Threat Synthesis</span>
            </div>

            <button
              type="submit"
              disabled={isLoading || !input.trim()}
              className="flex items-center justify-center gap-2 rounded-lg bg-amber-500 px-6 py-2.5 text-sm font-semibold text-slate-950 hover:bg-amber-400 focus:outline-none focus:ring-2 focus:ring-amber-400 focus:ring-offset-2 focus:ring-offset-slate-900 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-md shadow-amber-500/10 cursor-pointer"
            >
              {isLoading ? (
                <>
                  <div className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950 border-t-transparent" />
                  <span>Scanning Threat Vectors...</span>
                </>
              ) : (
                <>
                  <Search className="h-4 w-4" />
                  <span>Inspect & Verify Link</span>
                  <ArrowRight className="h-4 w-4 ml-0.5" />
                </>
              )}
            </button>
          </div>
        </form>

        {/* Live Loading Telemetry Indicator */}
        {isLoading && (
          <div className="mt-5 rounded-lg border border-amber-500/20 bg-amber-500/5 p-4 animate-pulse">
            <div className="flex items-center gap-3">
              <div className="h-3 w-3 rounded-full bg-amber-400 animate-ping" />
              <div className="space-y-1">
                <p className="text-xs font-semibold text-amber-300">
                  OSINT PIPELINE ACTIVE
                </p>
                <p className="text-xs font-mono text-slate-300">
                  {loadingSteps[loadingPhase]}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Quick Test Samples */}
        <div className="mt-6 border-t border-slate-800/80 pt-5">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
            One-Click Test Samples (Real-World Attack Vectors):
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
            {samples.map((sample) => (
              <button
                key={sample.id}
                type="button"
                onClick={() => handleSelectSample(sample.rawText)}
                disabled={isLoading}
                className="group flex flex-col text-left rounded-lg border border-slate-800 bg-slate-950/70 p-3 hover:border-slate-700 hover:bg-slate-900 transition-all text-xs"
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-semibold text-slate-200 group-hover:text-amber-400 transition-colors">
                    {sample.label}
                  </span>
                  {sample.riskExpectation === 'HIGH_RISK' ? (
                    <span className="text-[10px] font-mono font-medium text-rose-400">
                      Scam Test
                    </span>
                  ) : (
                    <span className="text-[10px] font-mono font-medium text-emerald-400">
                      Safe Test
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 truncate font-mono">
                  {sample.url}
                </p>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
