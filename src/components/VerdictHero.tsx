import React from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  Share2,
  Copy,
  Check,
  Binary,
  Globe2,
  Lock,
  Database,
  Flame,
} from 'lucide-react';
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
  const {
    verdict,
    riskLevel,
    riskScore,
    targetDomain,
    lexical,
    homoglyph,
    dom,
    threatIntel,
    rdap,
    ssl,
  } = result;

  const handleCopyLink = () => {
    navigator.clipboard.writeText(result.extractedUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isMalicious = riskLevel === 'MALICIOUS';
  const isSuspicious = riskLevel === 'SUSPICIOUS';
  const isSafe = riskLevel === 'SAFE';

  const themeConfig = isMalicious
    ? {
        border: 'border-rose-600/60',
        bg: 'bg-rose-950/20',
        glow: 'shadow-rose-900/20',
        badgeBg: 'text-rose-400 border border-rose-500/30 bg-rose-500/10',
        barColor: 'bg-rose-500',
        headline: 'MALICIOUS / HIGH PHISHING RISK',
        statusDesc: 'MALICIOUS THREAT DETECTED · DO NOT CLICK',
        icon: AlertOctagon,
        iconColor: 'text-rose-400',
      }
    : isSuspicious
    ? {
        border: 'border-amber-600/60',
        bg: 'bg-amber-950/20',
        glow: 'shadow-amber-900/20',
        badgeBg: 'text-amber-400 border border-amber-500/30 bg-amber-500/10',
        barColor: 'bg-amber-500',
        headline: 'SUSPICIOUS LINK',
        statusDesc: 'SUSPICIOUS LINK · EXERCISE HIGH CAUTION',
        icon: AlertTriangle,
        iconColor: 'text-amber-400',
      }
    : {
        border: 'border-emerald-600/60',
        bg: 'bg-emerald-950/20',
        glow: 'shadow-emerald-900/20',
        badgeBg: 'text-emerald-400 border border-emerald-500/30 bg-emerald-500/10',
        barColor: 'bg-emerald-500',
        headline: 'LOW RISK / SAFE',
        statusDesc: 'LOW RISK / SAFE · CLEAN DOMAIN TELEMETRY',
        icon: CheckCircle2,
        iconColor: 'text-emerald-400',
      };

  const IconComponent = themeConfig.icon;

  return (
    <div
      className={`relative overflow-hidden rounded-xl border ${themeConfig.border} ${themeConfig.bg} p-6 sm:p-8 shadow-xl ${themeConfig.glow} backdrop-blur-sm transition-all`}
    >
      {/* Background radial accent */}
      <div
        className={`pointer-events-none absolute -right-20 -top-20 h-64 w-64 rounded-full ${
          isMalicious
            ? 'bg-rose-500/10'
            : isSuspicious
            ? 'bg-amber-500/10'
            : 'bg-emerald-500/10'
        } blur-3xl`}
      />

      <div className="relative z-10 flex flex-col gap-6">
        {/* Top Header Row */}
        <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
          <div className="flex items-start gap-4">
            <div
              className={`mt-1 flex h-14 w-14 shrink-0 items-center justify-center rounded-xl bg-slate-900 border border-slate-800 ${themeConfig.iconColor}`}
            >
              <IconComponent className="h-8 w-8" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2 mb-1.5">
                <span
                  className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold tracking-wider uppercase ${themeConfig.badgeBg}`}
                >
                  {isMalicious
                    ? 'Malicious / High Risk (Score 60-100)'
                    : isSuspicious
                    ? 'Suspicious (Score 30-59)'
                    : 'Low Risk / Safe (Score 0-29)'}
                </span>
                <span className="text-slate-600">·</span>
                <span className="text-xs text-slate-400 font-mono">
                  {result.executionTimeMs}ms execution
                </span>
              </div>
              <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white text-balance">
                {verdict.verdictTitle || themeConfig.headline}
              </h2>
              <div className="mt-1 flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400">
                <span>Target:</span>
                <span className="text-slate-200 font-semibold">{targetDomain}</span>
                {homoglyph.isTyposquat && homoglyph.matchedBrand && (
                  <>
                    <span className="text-slate-600">·</span>
                    <span className="text-rose-400 font-bold flex items-center gap-1">
                      <Flame className="h-3 w-3" />
                      Spoofing {homoglyph.matchedBrand}
                    </span>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Big Risk Score Meter */}
          <div className="flex flex-row md:flex-col items-center md:items-end justify-between border-t md:border-t-0 border-slate-800 pt-3 md:pt-0">
            <div className="text-left md:text-right">
              <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
                Composite Risk Score
              </span>
              <div className="flex items-baseline md:justify-end gap-1">
                <span
                  className={`text-5xl font-black font-mono tabular-nums ${themeConfig.iconColor}`}
                >
                  {riskScore}
                </span>
                <span className="text-base font-mono text-slate-500">/ 100</span>
              </div>
            </div>
            <div className="w-36 sm:w-48 mt-2">
              <div className="h-3 w-full overflow-hidden rounded-full bg-slate-950 border border-slate-800 p-0.5">
                <div
                  className={`h-full rounded-full ${themeConfig.barColor} transition-all duration-700`}
                  style={{ width: `${Math.max(4, riskScore)}%` }}
                />
              </div>
              <div className="mt-1.5 flex justify-between text-[10px] font-mono text-slate-400">
                <span className="text-emerald-400 font-medium">Safe (0-29)</span>
                <span className="text-amber-400 font-medium">Suspicious (30-59)</span>
                <span className="text-rose-400 font-medium">Malicious (60+)</span>
              </div>
            </div>
          </div>
        </div>

        {/* Plain-English Assessment */}
        <div className="rounded-lg border border-slate-800/80 bg-slate-950/70 p-4 sm:p-5">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Deterministic Security Assessment
            </h3>
            <span className="text-[11px] font-mono text-amber-400/90 font-medium">
              {verdict.attackVector}
            </span>
          </div>
          <p className="text-sm sm:text-base text-slate-200 leading-relaxed">
            {verdict.plainEnglishSummary}
          </p>

          {verdict.dangerExplanation && (
            <div className="mt-3.5 border-t border-slate-800/60 pt-3 text-xs sm:text-sm text-slate-300 flex items-start gap-2">
              <span className="font-semibold text-rose-400 shrink-0">Security Warning:</span>
              <span>{verdict.dangerExplanation}</span>
            </div>
          )}
        </div>

        {/* Quick OSINT Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
            <div className="flex items-center gap-1.5 text-slate-400 text-[11px] mb-1">
              <Binary className="h-3.5 w-3.5 text-amber-400" />
              <span>Shannon Entropy</span>
            </div>
            <span
              className={`font-mono font-semibold tabular-nums ${
                lexical.hostnameEntropy >= 3.85 ? 'text-amber-400 font-bold' : 'text-slate-200'
              }`}
            >
              {lexical.hostnameEntropy} bits{' '}
              <span className="text-[10px] text-slate-500 font-normal">
                {lexical.hostnameEntropy >= 3.85 ? '(Elevated)' : '(Normal)'}
              </span>
            </span>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
            <div className="flex items-center gap-1.5 text-slate-400 text-[11px] mb-1">
              <Globe2 className="h-3.5 w-3.5 text-emerald-400" />
              <span>Domain Age</span>
            </div>
            <span
              className={`font-mono font-semibold tabular-nums ${
                rdap.isBrandNew
                  ? 'text-rose-400 font-bold'
                  : rdap.isRecentlyRegistered
                  ? 'text-amber-400'
                  : 'text-slate-200'
              }`}
            >
              {rdap.domainAgeDays !== undefined ? `${rdap.domainAgeDays} days` : 'Private / Hidden'}
            </span>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
            <div className="flex items-center gap-1.5 text-slate-400 text-[11px] mb-1">
              <Lock className="h-3.5 w-3.5 text-blue-400" />
              <span>SSL / TLS Encryption</span>
            </div>
            <span
              className={`font-mono font-semibold truncate block ${
                ssl.hasSsl && ssl.valid ? 'text-slate-200' : 'text-rose-400'
              }`}
            >
              {ssl.hasSsl
                ? ssl.valid
                  ? `${ssl.issuerOrg || 'Valid TLS'}`
                  : 'Untrusted Cert'
                : 'No SSL (Plaintext)'}
            </span>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
            <div className="flex items-center gap-1.5 text-slate-400 text-[11px] mb-1">
              <Database className="h-3.5 w-3.5 text-purple-400" />
              <span>Threat Intelligence</span>
            </div>
            <span
              className={`font-mono font-semibold ${
                threatIntel.knownThreatListMatched ? 'text-rose-400 font-bold' : 'text-emerald-400'
              }`}
            >
              {threatIntel.knownThreatListMatched
                ? 'Flagged on Blocklists'
                : 'URLhaus / PhishTank Clean'}
            </span>
          </div>
        </div>

        {/* Actions Button Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
          <div className="flex items-center gap-2">
            <button
              onClick={onOpenActionPlan}
              className={`flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition-all shadow-sm cursor-pointer ${
                isMalicious
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
              className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/80 px-3.5 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-colors cursor-pointer"
            >
              <Share2 className="h-3.5 w-3.5 text-slate-400" />
              <span>Export Report</span>
            </button>
          </div>

          <button
            onClick={handleCopyLink}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
          >
            {copied ? (
              <Check className="h-3.5 w-3.5 text-emerald-400" />
            ) : (
              <Copy className="h-3.5 w-3.5" />
            )}
            <span>{copied ? 'Link Copied' : 'Copy Scanned URL'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
