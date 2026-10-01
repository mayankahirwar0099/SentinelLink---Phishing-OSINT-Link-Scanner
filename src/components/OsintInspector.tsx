import React, { useState } from 'react';
import {
  Shield,
  Clock,
  Lock,
  GitCommit,
  Network,
  Binary,
  Type,
  FileCode2,
  Database,
  ExternalLink,
  ChevronRight,
  AlertCircle,
  CheckCircle2,
} from 'lucide-react';
import type { ScanResult } from '../types/scanner.js';
import { BreakdownTable } from './BreakdownTable.js';

interface OsintInspectorProps {
  result: ScanResult;
}

type TabType =
  | 'breakdown'
  | 'lexical'
  | 'homoglyph'
  | 'dom'
  | 'network'
  | 'ssl'
  | 'rdap'
  | 'redirects'
  | 'intel';

export const OsintInspector: React.FC<OsintInspectorProps> = ({ result }) => {
  const [activeTab, setActiveTab] = useState<TabType>('breakdown');
  const {
    indicators,
    lexical,
    homoglyph,
    dom,
    threatIntel,
    rdap,
    ssl,
    redirects,
    dns,
    finalUrl,
    targetDomain,
    apexDomain,
  } = result;

  return (
    <div className="space-y-6">
      {/* 1. Primary Breakdown Table of Checks Passed/Failed */}
      <BreakdownTable indicators={indicators} />

      {/* 2. Deep-Dive OSINT Telemetry Tab Suite */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden backdrop-blur-sm">
        {/* Tab Controls Bar */}
        <div className="border-b border-slate-800 bg-slate-950/70 p-4 sm:px-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-3">
            <div>
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
                Deep-Dive OSINT & Telemetry Inspector
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Raw technical signals gathered across Shannon entropy, DOM parser, DNS SPF, and TLS handshakes.
              </p>
            </div>
            <div className="text-xs font-mono text-slate-400">
              Target: <span className="text-amber-400 font-semibold">{apexDomain}</span>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-1.5 p-1 bg-slate-900 rounded-lg border border-slate-800">
            <button
              onClick={() => setActiveTab('lexical')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                activeTab === 'lexical'
                  ? 'bg-slate-800 text-amber-400 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Binary className="h-3.5 w-3.5" />
              <span>Lexical & Entropy</span>
            </button>

            <button
              onClick={() => setActiveTab('homoglyph')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                activeTab === 'homoglyph'
                  ? 'bg-slate-800 text-amber-400 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Type className="h-3.5 w-3.5" />
              <span>Homoglyph & Brand</span>
            </button>

            <button
              onClick={() => setActiveTab('dom')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                activeTab === 'dom'
                  ? 'bg-slate-800 text-amber-400 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCode2 className="h-3.5 w-3.5" />
              <span>DOM & Form Security</span>
            </button>

            <button
              onClick={() => setActiveTab('network')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                activeTab === 'network'
                  ? 'bg-slate-800 text-amber-400 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Network className="h-3.5 w-3.5" />
              <span>DNS & SPF</span>
            </button>

            <button
              onClick={() => setActiveTab('ssl')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                activeTab === 'ssl'
                  ? 'bg-slate-800 text-amber-400 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Lock className="h-3.5 w-3.5" />
              <span>SSL / TLS</span>
            </button>

            <button
              onClick={() => setActiveTab('rdap')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                activeTab === 'rdap'
                  ? 'bg-slate-800 text-amber-400 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Clock className="h-3.5 w-3.5" />
              <span>RDAP & Whois</span>
            </button>

            <button
              onClick={() => setActiveTab('redirects')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                activeTab === 'redirects'
                  ? 'bg-slate-800 text-amber-400 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <GitCommit className="h-3.5 w-3.5" />
              <span>Redirects ({redirects.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('intel')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                activeTab === 'intel'
                  ? 'bg-slate-800 text-amber-400 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Database className="h-3.5 w-3.5" />
              <span>Threat Intel Feeds</span>
            </button>
          </div>
        </div>

        {/* Tab Body */}
        <div className="p-5 sm:p-6 text-xs font-mono">
          {/* 1. Lexical & Entropy Tab */}
          {activeTab === 'lexical' && (
            <div className="space-y-4 font-mono">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                    Shannon Entropy & Randomness
                  </span>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Hostname Entropy:</span>
                    <span
                      className={`font-semibold ${
                        lexical.hostnameEntropy >= 3.85 ? 'text-amber-400 font-bold' : 'text-slate-200'
                      }`}
                    >
                      {lexical.hostnameEntropy} bits{' '}
                      {lexical.hostnameEntropy >= 3.85 ? '(Algorithmic / DGA Risk)' : '(Normal)'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Path Entropy:</span>
                    <span className="text-slate-200">{lexical.pathEntropy} bits</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Total URL Length:</span>
                    <span className="text-slate-200">{lexical.urlLength} characters</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Hyphen Count:</span>
                    <span className="text-slate-200">{lexical.hyphenCount} hyphens</span>
                  </div>
                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                    Structural Host Tokens
                  </span>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Raw IP Hostname:</span>
                    <span className={lexical.hasRawIp ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                      {lexical.hasRawIp ? 'YES (Numeric IP)' : 'NO (Domain Name)'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Subdomain Count:</span>
                    <span className="text-slate-200">{lexical.subdomainCount}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Subdomains List:</span>
                    <span className="text-slate-200">
                      {lexical.subdomains.length > 0 ? lexical.subdomains.join('.') : 'None (Apex)'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">TLD Extension:</span>
                    <span className={lexical.isAbuseTld ? 'text-rose-400 font-bold' : 'text-slate-200'}>
                      .{lexical.tld} {lexical.isAbuseTld ? '(Flagged High Abuse)' : ''}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* 2. Homoglyph & Typosquat Tab */}
          {activeTab === 'homoglyph' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                    Punycode & Script Confusables
                  </span>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Punycode Encoding:</span>
                    <span className={homoglyph.isPunycode ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                      {homoglyph.isPunycode ? 'YES (xn-- detected)' : 'None (Standard ASCII)'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Mixed Cyrillic / Greek Scripts:</span>
                    <span className={homoglyph.hasMixedScript ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                      {homoglyph.hasMixedScript ? 'YES (Homoglyphs detected)' : 'Clean (No mixed scripts)'}
                    </span>
                  </div>
                  {homoglyph.confusableCharacters.length > 0 && (
                    <div className="py-1 border-b border-slate-900">
                      <span className="text-slate-500 block mb-1">Confusables:</span>
                      <span className="text-rose-300">{homoglyph.confusableCharacters.join(', ')}</span>
                    </div>
                  )}
                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                    Levenshtein & Combosquatting Matrix
                  </span>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Typosquat Triggered:</span>
                    <span className={homoglyph.isTyposquat ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                      {homoglyph.isTyposquat ? 'YES (Mimicking Brand)' : 'Clean'}
                    </span>
                  </div>
                  {homoglyph.matchedBrand && (
                    <>
                      <div className="flex justify-between py-1 border-b border-slate-900">
                        <span className="text-slate-500">Targeted Brand:</span>
                        <span className="text-rose-400 font-bold">{homoglyph.matchedBrand}</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-900">
                        <span className="text-slate-500">Official Portal:</span>
                        <span className="text-slate-200">{homoglyph.officialDomain}</span>
                      </div>
                      {homoglyph.levenshteinDistance !== undefined && (
                        <div className="flex justify-between py-1 border-b border-slate-900">
                          <span className="text-slate-500">Levenshtein Edit Distance:</span>
                          <span className="text-amber-400 font-bold">
                            {homoglyph.levenshteinDistance} edit(s)
                          </span>
                        </div>
                      )}
                    </>
                  )}
                  {homoglyph.typosquatDetails && (
                    <p className="text-[11px] text-slate-300 font-sans mt-2 italic">
                      {homoglyph.typosquatDetails}
                    </p>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* 3. DOM & Form Security Tab */}
          {activeTab === 'dom' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                    HTML Form Controls & Credentials
                  </span>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">DOM Body Inspected:</span>
                    <span className={dom.htmlInspected ? 'text-emerald-400' : 'text-slate-400'}>
                      {dom.htmlInspected ? 'Completed (Raw HTML Analyzed)' : 'Inaccessible'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Password Input Field:</span>
                    <span className={dom.hasPasswordInput ? 'text-amber-400 font-bold' : 'text-slate-300'}>
                      {dom.hasPasswordInput ? 'DETECTED in DOM' : 'None detected'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Plaintext Password (HTTP):</span>
                    <span className={dom.hasUnencryptedPasswordInput ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                      {dom.hasUnencryptedPasswordInput ? 'CRITICAL RISK (Unencrypted)' : 'NO'}
                    </span>
                  </div>
                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                    Framing & Form Destination Actions
                  </span>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Concealed Hidden Iframes:</span>
                    <span className={dom.hiddenIframeDetected ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                      {dom.hiddenIframeDetected ? `YES (${dom.hiddenIframeCount} hidden frame)` : 'None (Clean)'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Off-Domain Form Action:</span>
                    <span className={dom.suspiciousFormAction ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                      {dom.suspiciousFormAction ? 'YES (Posts off-domain)' : 'Standard'}
                    </span>
                  </div>
                  {dom.pageTitle && (
                    <div className="py-1 border-b border-slate-900">
                      <span className="text-slate-500 block mb-0.5">Page &lt;title&gt;:</span>
                      <span className="text-slate-200 truncate block">"{dom.pageTitle}"</span>
                    </div>
                  )}
                </div>
              </div>

              {dom.findings.length > 0 && (
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 font-sans text-xs">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-2 font-sans">
                    DOM Security Findings
                  </span>
                  <ul className="space-y-1.5 text-slate-300">
                    {dom.findings.map((f, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <span className="text-amber-400 mt-0.5">•</span>
                        <span>{f}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* 4. DNS & SPF Tab */}
          {activeTab === 'network' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                    IP Resolution (A & AAAA Records)
                  </span>
                  {dns.resolvedIps.length > 0 ? (
                    <ul className="space-y-1 text-slate-200">
                      {dns.resolvedIps.map((ip, i) => (
                        <li key={i} className="flex justify-between">
                          <span className="text-slate-500">IPv4 #{i + 1}:</span>
                          <span className="font-semibold">{ip}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-rose-400">NXDOMAIN (Unresolved Hostname)</p>
                  )}

                  {dns.reverseDns && dns.reverseDns.length > 0 && (
                    <div className="border-t border-slate-900 pt-2 text-slate-300">
                      <span className="text-slate-500 block mb-1">Reverse PTR DNS:</span>
                      <span className="text-slate-300">{dns.reverseDns.join(', ')}</span>
                    </div>
                  )}
                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                    Email Infrastructure (MX & SPF)
                  </span>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">SPF Verification:</span>
                    <span className={dns.hasSpf ? 'text-emerald-400 font-bold' : 'text-amber-400'}>
                      {dns.hasSpf ? 'v=spf1 Configured' : 'Missing SPF Record'}
                    </span>
                  </div>
                  {dns.spfRecord && (
                    <div className="py-1 border-b border-slate-900">
                      <span className="text-slate-500 block mb-0.5">SPF Policy String:</span>
                      <span className="text-slate-300 break-all text-[11px]">{dns.spfRecord}</span>
                    </div>
                  )}
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Mail Exchange (MX):</span>
                    <span className={dns.hasMxRecords ? 'text-emerald-400 font-bold' : 'text-rose-400'}>
                      {dns.hasMxRecords ? `${dns.mxRecords.length} Mail Servers` : 'Zero MX Infrastructure'}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* 5. SSL / TLS Tab */}
          {activeTab === 'ssl' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                    Certificate Authority & Trust
                  </span>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">SSL Active:</span>
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
                    <span className="text-slate-500">Issuer Organization:</span>
                    <span className="text-slate-200">{ssl.issuerOrg || 'N/A'}</span>
                  </div>
                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                    Validity Period
                  </span>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Days Remaining:</span>
                    <span className="text-slate-200">
                      {ssl.daysRemaining !== undefined ? `${ssl.daysRemaining} days` : 'N/A'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Self-Signed:</span>
                    <span className={ssl.isSelfSigned ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                      {ssl.isSelfSigned ? 'YES (Untrusted Self-Signed)' : 'No'}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* 6. RDAP & Whois Tab */}
          {activeTab === 'rdap' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                    Registration Lifecycle
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
                        : 'Hidden / Private'}
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

                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                    Registrar Identity
                  </span>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">Registrar:</span>
                    <span className="text-slate-200">{rdap.registrar || 'Private / Redacted'}</span>
                  </div>
                  {rdap.status && rdap.status.length > 0 && (
                    <div>
                      <span className="text-slate-500 block mb-1">Status Flags:</span>
                      <div className="flex flex-wrap gap-1">
                        {rdap.status.map((st, i) => (
                          <span
                            key={i}
                            className="rounded bg-slate-900 px-1.5 py-0.5 border border-slate-800 text-[10px]"
                          >
                            {st}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* 7. Redirect Chain Tab */}
          {activeTab === 'redirects' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                <span>Traced Hops from initial click to landing page:</span>
                <span className="font-mono text-slate-300">
                  Landing: <span className="text-amber-300 font-semibold">{finalUrl}</span>
                </span>
              </div>

              {redirects.length === 0 ? (
                <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4 text-xs text-slate-400">
                  Direct connection. No HTTP redirection hops recorded.
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

          {/* 8. Threat Intel Feeds Tab */}
          {activeTab === 'intel' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                    abuse.ch URLhaus Database
                  </span>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">URLhaus Match:</span>
                    <span
                      className={
                        threatIntel.urlhausMatched ? 'text-rose-400 font-bold' : 'text-emerald-400'
                      }
                    >
                      {threatIntel.urlhausMatched ? 'MATCHED (Malicious Feed)' : 'CLEAN (Not Listed)'}
                    </span>
                  </div>
                  {threatIntel.urlhausThreat && (
                    <div className="flex justify-between py-1 border-b border-slate-900">
                      <span className="text-slate-500">Cataloged Threat:</span>
                      <span className="text-rose-400 font-semibold">{threatIntel.urlhausThreat}</span>
                    </div>
                  )}
                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-2.5">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block font-sans">
                    PhishTank Community Feed
                  </span>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-500">PhishTank Match:</span>
                    <span
                      className={
                        threatIntel.phishtankMatched ? 'text-rose-400 font-bold' : 'text-emerald-400'
                      }
                    >
                      {threatIntel.phishtankMatched ? 'MATCHED (Active Phish)' : 'CLEAN (Not Listed)'}
                    </span>
                  </div>
                  {threatIntel.phishtankTarget && (
                    <div className="flex justify-between py-1 border-b border-slate-900">
                      <span className="text-slate-500">Target Signature:</span>
                      <span className="text-rose-400 font-semibold">{threatIntel.phishtankTarget}</span>
                    </div>
                  )}
                </div>
              </div>

              {threatIntel.details.length > 0 && (
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 font-sans text-xs">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-2 font-sans">
                    Feed Intelligence Details
                  </span>
                  <ul className="space-y-1 text-slate-300">
                    {threatIntel.details.map((d, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <span className="text-rose-400 mt-0.5">•</span>
                        <span>{d}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
