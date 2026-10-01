import React from 'react';
import { AlertOctagon, AlertTriangle, CheckCircle2, ShieldAlert, ShieldCheck, ExternalLink, Share2, Copy, Check } from 'lucide-react';
import type { ScanResult } from '../types/scanner.js';

interface VerdictHeroProps {
  result: ScanResult;
  onOpenActionPlan: () => void;
  onOpenExportModal: () => void;
}

export const VerdictHero: React.FC<VerdictHeroProps> = ({
  result,
  onOpenActionPlan,
  onOpenExportModal,
}) => {
  const [copied, setCopied] = React.useState(false);
  const { aiAnalysis, riskLevel, riskScore, targetDomain, brandCheck, rdap, ssl } = result;

  const handleCopyLink = () => {
    navigator.clipboard.writeText(result.extractedUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isHighRisk = riskLevel === 'HIGH_RISK';
  const isSuspicious = riskLevel === 'SUSPICIOUS';
  const isSafe = riskLevel === 'SAFE' || riskLevel === 'LOW_RISK';

  const themeConfig = isHighRisk
    ? {
        border: 'border-rose-600/60',
        bg: 'bg-rose-950/20',
        glow: 'shadow-rose-900/20',
        badgeBg: 'text-rose-400',
        barColor: 'bg-rose-500',
        headline: 'CRITICAL THREAT: HIGH RISK PHISHING',
        statusDesc: 'DO NOT CLICK · MALICIOUS INFRASTRUCTURE DETECTED',
        icon: AlertOctagon,
        iconColor: 'text-rose-400',
      }
    : isSuspicious
    ? {
        border: 'border-amber-600/60',
        bg: 'bg-amber-950/20',
        glow: 'shadow-amber-900/20',
        badgeBg: 'text-amber-400',
        barColor: 'bg-amber-500',
        headline: 'CAUTION: SUSPICIOUS & UNVERIFIED LINK',
        statusDesc: 'EXERCISE HIGH CAUTION · UNVERIFIED ORIGIN',
        icon: AlertTriangle,
        iconColor: 'text-amber-400',
      }
    : {
        border: 'border-emerald-600/60',
        bg: 'bg-emerald-950/20',
        glow: 'shadow-emerald-900/20',
        badgeBg: 'text-emerald-400',
        barColor: 'bg-emerald-500',
        headline: 'SAFE: ESTABLISHED DOMAIN INFRASTRUCTURE',
        statusDesc: 'NO DECEPTIVE THREAT SIGNATURES FOUND',
        icon: CheckCircle2,
        iconColor: 'text-emerald-400',
      };

  const IconComponent = themeConfig.icon;

  return (
    <div className={`relative overflow-hidden rounded-xl border ${themeConfig.border} ${themeConfig.bg} p-6 sm:p-8 shadow-xl ${themeConfig.glow} backdrop-blur-sm transition-all`}>
      {/* Background radial accent */}
      <div
        className={`pointer-events-none absolute -right-20 -top-20 h-64 w-64 rounded-full ${
          isHighRisk ? 'bg-rose-500/10' : isSuspicious ? 'bg-amber-500/10' : 'bg-emerald-500/10'
        } blur-3xl`}
      />

      <div className="relative z-10 flex flex-col gap-6">
        {/* Top Header Row */}
        <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className={`mt-1 flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-slate-900 border border-slate-800 ${themeConfig.iconColor}`}>
              <IconComponent className="h-7 w-7" />
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className={`text-xs font-mono font-bold tracking-wider uppercase ${themeConfig.badgeBg}`}>
                  {themeConfig.statusDesc}
                </span>
                <span className="text-slate-600">·</span>
                <span className="text-xs text-slate-400 font-mono">
                  Scan Time: {result.executionTimeMs}ms
                </span>
              </div>
              <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white text-balance">
                {aiAnalysis.title || themeConfig.headline}
              </h2>
              <div className="mt-1 flex items-center gap-2 text-xs font-mono text-slate-400">
                <span>Domain:</span>
                <span className="text-slate-200 font-semibold">{targetDomain}</span>
                {brandCheck.isImpersonating && (
                  <>
                    <span className="text-slate-600">·</span>
                    <span className="text-rose-400 font-bold">Impersonating {brandCheck.targetedBrand}</span>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Threat Meter / Score Dial */}
          <div className="flex flex-row md:flex-col items-center md:items-end justify-between border-t md:border-t-0 border-slate-800 pt-3 md:pt-0">
            <div className="text-left md:text-right">
              <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
                Threat Score
              </span>
              <div className="flex items-baseline md:justify-end gap-1">
                <span className={`text-4xl font-extrabold font-mono tabular-nums ${themeConfig.iconColor}`}>
                  {riskScore}
                </span>
                <span className="text-sm font-mono text-slate-500">/ 100</span>
              </div>
            </div>
            <div className="w-36 sm:w-44 mt-2">
              <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-950 border border-slate-800">
                <div
                  className={`h-full ${themeConfig.barColor} transition-all duration-700`}
                  style={{ width: `${Math.max(5, riskScore)}%` }}
                />
              </div>
              <div className="mt-1 flex justify-between text-[10px] font-mono text-slate-500">
                <span>Safe (0)</span>
                <span>Critical (100)</span>
              </div>
            </div>
          </div>
        </div>

        {/* Plain-English Breakdown for Non-Technical Users */}
        <div className="rounded-lg border border-slate-800/80 bg-slate-950/70 p-4 sm:p-5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
            Plain-English Security Assessment
          </h3>
          <p className="text-sm sm:text-base text-slate-200 leading-relaxed">
            {aiAnalysis.plainEnglishSummary}
          </p>

          {aiAnalysis.dangerExplanation && (
            <div className="mt-3.5 border-t border-slate-800/60 pt-3 text-xs sm:text-sm text-slate-400 flex items-start gap-2">
              <span className="font-semibold text-rose-400 shrink-0">Potential Danger:</span>
              <span>{aiAnalysis.dangerExplanation}</span>
            </div>
          )}
        </div>

        {/* Quick Facts Strip (Zero-Pill Metadata) */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
            <span className="text-slate-400 block text-[11px]">Domain Age</span>
            <span className="font-mono font-semibold text-slate-200 tabular-nums">
              {rdap.domainAgeDays !== undefined
                ? `${rdap.domainAgeDays} days old`
                : 'Hidden / Private'}
            </span>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
            <span className="text-slate-400 block text-[11px]">SSL Encryption</span>
            <span className="font-mono font-semibold text-slate-200">
              {ssl.hasSsl
                ? ssl.valid
                  ? `${ssl.issuerOrg || 'Valid TLS'}`
                  : 'Invalid / Expired'
                : 'No SSL (Plaintext)'}
            </span>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
            <span className="text-slate-400 block text-[11px]">Redirection Hops</span>
            <span className="font-mono font-semibold text-slate-200 tabular-nums">
              {result.redirects.length > 0 ? `${result.redirects.length} hop(s)` : 'Direct link'}
            </span>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
            <span className="text-slate-400 block text-[11px]">Attack Vector</span>
            <span className="font-semibold text-slate-200 truncate block">
              {aiAnalysis.attackVector || 'Web Link'}
            </span>
          </div>
        </div>

        {/* Actions Button Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
          <div className="flex items-center gap-2">
            <button
              onClick={onOpenActionPlan}
              className={`flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition-all shadow-sm ${
                isHighRisk
                  ? 'bg-rose-500 text-white hover:bg-rose-400'
                  : isSuspicious
                  ? 'bg-amber-500 text-slate-950 hover:bg-amber-400'
                  : 'bg-slate-800 text-slate-100 hover:bg-slate-700'
              }`}
            >
              <ShieldAlert className="h-4 w-4" />
              <span>Recommended Next Steps</span>
            </button>

            <button
              onClick={onOpenExportModal}
              className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/80 px-3.5 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
            >
              <Share2 className="h-3.5 w-3.5 text-slate-400" />
              <span>Export Report</span>
            </button>
          </div>

          <button
            onClick={handleCopyLink}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            <span>{copied ? 'Link Copied' : 'Copy Scanned URL'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
