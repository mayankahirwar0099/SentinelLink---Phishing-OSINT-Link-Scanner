import React, { useState } from 'react';
import {
  Shield,
  Clock,
  Lock,
  GitCommit,
  Network,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Info,
  ExternalLink,
  ChevronRight,
} from 'lucide-react';
import type { ScanResult } from '../types/scanner.js';

interface OsintInspectorProps {
  result: ScanResult;
}

type TabType = 'matrix' | 'domain' | 'ssl' | 'redirects' | 'dns';

export const OsintInspector: React.FC<OsintInspectorProps> = ({ result }) => {
  const [activeTab, setActiveTab] = useState<TabType>('matrix');
  const { indicators, rdap, ssl, redirects, dns, finalUrl, targetDomain, apexDomain } = result;

  const failedCount = indicators.filter((i) => !i.passed).length;
  const passedCount = indicators.filter((i) => i.passed).length;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden backdrop-blur-sm">
      {/* Header with Segmented Filter Controls */}
      <div className="border-b border-slate-800 bg-slate-950/70 p-4 sm:px-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
              Technical OSINT & Telemetry Deep-Dive
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Live inspection results gathered from RDAP registry, TLS handshake, DNS lookups, and redirect probing.
            </p>
          </div>

          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
            <span className="text-rose-400 font-semibold">{failedCount} alerts</span>
            <span>·</span>
            <span className="text-emerald-400 font-semibold">{passedCount} verified clean</span>
          </div>
        </div>

        {/* Tab Controls (Functional Buttons) */}
        <div className="mt-4 flex flex-wrap items-center gap-1 p-1 bg-slate-900 rounded-lg border border-slate-800">
          <button
            onClick={() => setActiveTab('matrix')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'matrix'
                ? 'bg-slate-800 text-amber-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Shield className="h-3.5 w-3.5" />
            <span>Threat Matrix</span>
          </button>

          <button
            onClick={() => setActiveTab('domain')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'domain'
                ? 'bg-slate-800 text-amber-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Clock className="h-3.5 w-3.5" />
            <span>Domain & Whois</span>
          </button>

          <button
            onClick={() => setActiveTab('ssl')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'ssl'
                ? 'bg-slate-800 text-amber-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Lock className="h-3.5 w-3.5" />
            <span>SSL / TLS Audit</span>
          </button>

          <button
            onClick={() => setActiveTab('redirects')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'redirects'
                ? 'bg-slate-800 text-amber-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <GitCommit className="h-3.5 w-3.5" />
            <span>Redirects ({redirects.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('dns')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'dns'
                ? 'bg-slate-800 text-amber-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Network className="h-3.5 w-3.5" />
            <span>DNS & Network</span>
          </button>
        </div>
      </div>

      {/* Tab Contents */}
      <div className="p-5 sm:p-6">
        {/* Tab 1: Threat Matrix */}
        {activeTab === 'matrix' && (
          <div className="space-y-3">
            <div className="grid grid-cols-1 gap-2.5">
              {indicators.map((ind) => {
                const isPassed = ind.passed;
                const isCritical = ind.severity === 'CRITICAL';
                const isHigh = ind.severity === 'HIGH';

                return (
                  <div
                    key={ind.id}
                    className={`flex items-start justify-between gap-3 rounded-lg border p-3.5 transition-colors ${
                      !isPassed
                        ? isCritical
                          ? 'border-rose-900/60 bg-rose-950/20'
                          : isHigh
                          ? 'border-amber-900/60 bg-amber-950/20'
                          : 'border-slate-800 bg-slate-950/50'
                        : 'border-slate-800/80 bg-slate-950/40'
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div className="mt-0.5 shrink-0">
                        {isPassed ? (
                          <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                        ) : isCritical ? (
                          <XCircle className="h-4 w-4 text-rose-400" />
                        ) : (
                          <AlertCircle className="h-4 w-4 text-amber-400" />
                        )}
                      </div>
                      <div>
                        <div className="flex items-center gap-2 mb-0.5">
                          <span className="text-xs sm:text-sm font-semibold text-slate-200">
                            {ind.title}
                          </span>
                          <span className="text-[10px] font-mono uppercase text-slate-500">
                            [{ind.category}]
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 leading-relaxed">
                          {ind.description}
                        </p>
                      </div>
                    </div>

                    <div className="shrink-0 text-right">
                      <span
                        className={`text-[10px] font-mono uppercase font-semibold ${
                          isPassed
                            ? 'text-emerald-400'
                            : isCritical
                            ? 'text-rose-400'
                            : 'text-amber-400'
                        }`}
                      >
                        {isPassed ? 'CLEAN' : ind.severity}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Tab 2: Domain & Whois RDAP */}
        {activeTab === 'domain' && (
          <div className="space-y-5">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                  Registry Identity
                </span>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Apex Domain:</span>
                  <span className="text-slate-200 font-semibold">{apexDomain}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Full Host:</span>
                  <span className="text-slate-200 break-all">{targetDomain}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Registrar Name:</span>
                  <span className="text-slate-200">{rdap.registrar || 'Private / Redacted'}</span>
                </div>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                  Lifecycle Timestamps
                </span>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Domain Age:</span>
                  <span
                    className={`font-semibold tabular-nums ${
                      rdap.isBrandNew
                        ? 'text-rose-400 font-bold'
                        : rdap.isRecentlyRegistered
                        ? 'text-amber-400'
                        : 'text-emerald-400'
                    }`}
                  >
                    {rdap.domainAgeDays !== undefined
                      ? `${rdap.domainAgeDays} days old`
                      : 'Unknown / Hidden'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Registration Date:</span>
                  <span className="text-slate-200">
                    {rdap.registrationDate
                      ? new Date(rdap.registrationDate).toLocaleDateString()
                      : 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Expiration Date:</span>
                  <span className="text-slate-200">
                    {rdap.expirationDate
                      ? new Date(rdap.expirationDate).toLocaleDateString()
                      : 'N/A'}
                  </span>
                </div>
              </div>
            </div>

            {rdap.status && rdap.status.length > 0 && (
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans mb-2">
                  Registry Status Flags (EPP Codes)
                </span>
                <div className="flex flex-wrap gap-2 text-xs font-mono text-slate-300">
                  {rdap.status.map((st, i) => (
                    <span
                      key={i}
                      className="rounded bg-slate-900 px-2 py-1 border border-slate-800 text-[11px]"
                    >
                      {st}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 3: SSL / TLS Audit */}
        {activeTab === 'ssl' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                  Certificate Authority & Trust
                </span>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">SSL Enabled:</span>
                  <span className={ssl.hasSsl ? 'text-emerald-400' : 'text-rose-400 font-bold'}>
                    {ssl.hasSsl ? 'Yes (HTTPS)' : 'No (Plaintext HTTP)'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Public Trust Valid:</span>
                  <span className={ssl.valid ? 'text-emerald-400' : 'text-rose-400 font-bold'}>
                    {ssl.valid ? 'Valid Certificate' : ssl.error || 'Untrusted / Invalid'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Issuer Org:</span>
                  <span className="text-slate-200">{ssl.issuerOrg || 'N/A'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Self-Signed:</span>
                  <span className={ssl.isSelfSigned ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                    {ssl.isSelfSigned ? 'YES (Untrusted)' : 'No'}
                  </span>
                </div>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                  Validity Period & SANs
                </span>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Days Remaining:</span>
                  <span
                    className={`tabular-nums ${
                      ssl.isExpired
                        ? 'text-rose-400 font-bold'
                        : (ssl.daysRemaining ?? 100) < 14
                        ? 'text-amber-400'
                        : 'text-slate-200'
                    }`}
                  >
                    {ssl.daysRemaining !== undefined
                      ? `${ssl.daysRemaining} days`
                      : 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Valid From:</span>
                  <span className="text-slate-200">
                    {ssl.validFrom ? new Date(ssl.validFrom).toLocaleDateString() : 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Valid Until:</span>
                  <span className="text-slate-200">
                    {ssl.validTo ? new Date(ssl.validTo).toLocaleDateString() : 'N/A'}
                  </span>
                </div>
              </div>
            </div>

            {ssl.sanList && ssl.sanList.length > 0 && (
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans mb-2">
                  Subject Alternative Names (SANs)
                </span>
                <div className="flex flex-wrap gap-1.5 text-xs font-mono text-slate-300">
                  {ssl.sanList.map((san, i) => (
                    <span
                      key={i}
                      className="rounded bg-slate-900 px-2 py-0.5 border border-slate-800 text-[11px]"
                    >
                      {san}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 4: Redirection Chain */}
        {activeTab === 'redirects' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span>Traced Hops from initial click to final landing:</span>
              <span className="font-mono text-slate-300">
                Final Target: <span className="text-amber-300 font-semibold">{finalUrl}</span>
              </span>
            </div>

            {redirects.length === 0 ? (
              <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4 text-xs text-slate-400">
                Direct link. No HTTP 301/302 redirection hops recorded.
              </div>
            ) : (
              <div className="space-y-2">
                {redirects.map((hop, idx) => (
                  <div
                    key={idx}
                    className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-xs font-mono"
                  >
                    <div className="flex items-center gap-2">
                      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-800 text-[10px] font-bold text-slate-300">
                        {idx + 1}
                      </span>
                      <span className="text-slate-200 break-all">{hop.url}</span>
                    </div>

                    <div className="flex items-center gap-3 shrink-0 text-slate-400 pl-7 sm:pl-0">
                      <span className="rounded bg-slate-900 px-2 py-0.5 border border-slate-800 text-[11px] font-bold text-amber-400">
                        HTTP {hop.statusCode || '200'}
                      </span>
                      <span>{hop.isHttps ? 'HTTPS' : 'HTTP'}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab 5: DNS & Network */}
        {activeTab === 'dns' && (
          <div className="space-y-4 text-xs font-mono">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                  Resolved IP Addresses (A / AAAA Records)
                </span>
                {dns.resolvedIps.length > 0 ? (
                  <ul className="space-y-1 text-slate-200">
                    {dns.resolvedIps.map((ip, i) => (
                      <li key={i} className="flex justify-between">
                        <span>IPv4 #{i + 1}:</span>
                        <span className="font-semibold">{ip}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-slate-500">No public IPv4 records resolved (NXDOMAIN).</p>
                )}

                {dns.ipv6.length > 0 && (
                  <div className="border-t border-slate-900 pt-2 text-slate-300">
                    <span className="text-slate-500 block mb-1">IPv6 Addresses:</span>
                    {dns.ipv6.map((ip6, i) => (
                      <span key={i} className="block text-[11px] text-slate-400">
                        {ip6}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                  Mail Exchange (MX) Infrastructure
                </span>
                {dns.hasMxRecords ? (
                  <ul className="space-y-1 text-slate-200">
                    {dns.mxRecords.map((mx, i) => (
                      <li key={i} className="flex justify-between">
                        <span className="text-slate-500">Priority {mx.priority}:</span>
                        <span className="font-semibold text-slate-300">{mx.exchange}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="text-rose-400/90 text-xs">
                    <p className="font-semibold">Zero MX Mail Records</p>
                    <p className="text-[11px] text-slate-500 mt-1">
                      Domain cannot receive official emails, common among disposable phishing campaigns.
                    </p>
                  </div>
                )}
              </div>
            </div>

            {dns.nsRecords.length > 0 && (
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans mb-2">
                  Authoritative Name Servers (NS)
                </span>
                <div className="flex flex-wrap gap-2 text-xs text-slate-300">
                  {dns.nsRecords.map((ns, i) => (
                    <span
                      key={i}
                      className="rounded bg-slate-900 px-2 py-1 border border-slate-800 text-[11px]"
                    >
                      {ns}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
