import React, { useState } from 'react';
import {
  ShieldAlert,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Filter,
  Layers,
  Code2,
  Type,
  FileCode2,
  Network,
  Database,
} from 'lucide-react';
import type { HeuristicIndicator, IndicatorModule } from '../types/scanner.js';

interface BreakdownTableProps {
  indicators: HeuristicIndicator[];
}

type FilterCategory = 'ALL' | 'FLAGGED' | IndicatorModule;

export const BreakdownTable: React.FC<BreakdownTableProps> = ({ indicators }) => {
  const [activeFilter, setActiveFilter] = useState<FilterCategory>('ALL');

  const flaggedCount = indicators.filter((i) => !i.passed).length;
  const passedCount = indicators.filter((i) => i.passed).length;
  const totalPoints = indicators
    .filter((i) => !i.passed)
    .reduce((sum, i) => sum + (i.points || 0), 0);

  const filteredIndicators = indicators.filter((ind) => {
    if (activeFilter === 'ALL') return true;
    if (activeFilter === 'FLAGGED') return !ind.passed;
    return ind.module === activeFilter;
  });

  const getModuleBadge = (mod: IndicatorModule) => {
    switch (mod) {
      case 'LEXICAL':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-blue-500/10 px-2 py-0.5 text-[10px] font-mono font-medium text-blue-400 border border-blue-500/20">
            <Code2 className="h-3 w-3" />
            Lexical
          </span>
        );
      case 'HOMOGLYPH':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-purple-500/10 px-2 py-0.5 text-[10px] font-mono font-medium text-purple-400 border border-purple-500/20">
            <Type className="h-3 w-3" />
            Homoglyph
          </span>
        );
      case 'DOM':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-amber-500/10 px-2 py-0.5 text-[10px] font-mono font-medium text-amber-400 border border-amber-500/20">
            <FileCode2 className="h-3 w-3" />
            DOM & Forms
          </span>
        );
      case 'NETWORK_OSINT':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-2 py-0.5 text-[10px] font-mono font-medium text-emerald-400 border border-emerald-500/20">
            <Network className="h-3 w-3" />
            OSINT
          </span>
        );
      case 'THREAT_FEED':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-rose-500/10 px-2 py-0.5 text-[10px] font-mono font-medium text-rose-400 border border-rose-500/20">
            <Database className="h-3 w-3" />
            Threat Intel
          </span>
        );
    }
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden backdrop-blur-sm">
      {/* Table Header & Filter Bar */}
      <div className="border-b border-slate-800 bg-slate-950/70 p-4 sm:p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-amber-400" />
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
                Deterministic Heuristic & Security Breakdown
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Transparent point evaluation across lexical structure, typosquatting, DOM inspection, and threat intelligence.
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="rounded bg-rose-500/10 border border-rose-500/30 px-2 py-1 text-rose-400 font-semibold">
              {flaggedCount} Flagged (+{totalPoints} pts)
            </span>
            <span className="rounded bg-emerald-500/10 border border-emerald-500/30 px-2 py-1 text-emerald-400 font-semibold">
              {passedCount} Passed Clean
            </span>
          </div>
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <button
            onClick={() => setActiveFilter('ALL')}
            className={`px-3 py-1.5 rounded-lg border font-medium transition-colors cursor-pointer ${
              activeFilter === 'ALL'
                ? 'bg-amber-500 text-slate-950 border-amber-500 font-semibold'
                : 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700'
            }`}
          >
            All Checks ({indicators.length})
          </button>

          <button
            onClick={() => setActiveFilter('FLAGGED')}
            className={`px-3 py-1.5 rounded-lg border font-medium transition-colors cursor-pointer ${
              activeFilter === 'FLAGGED'
                ? 'bg-rose-500 text-white border-rose-500 font-semibold'
                : 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700'
            }`}
          >
            Threat Triggers ({flaggedCount})
          </button>

          <button
            onClick={() => setActiveFilter('LEXICAL')}
            className={`px-3 py-1.5 rounded-lg border font-medium transition-colors cursor-pointer ${
              activeFilter === 'LEXICAL'
                ? 'bg-blue-600 text-white border-blue-600 font-semibold'
                : 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700'
            }`}
          >
            Lexical & Entropy
          </button>

          <button
            onClick={() => setActiveFilter('HOMOGLYPH')}
            className={`px-3 py-1.5 rounded-lg border font-medium transition-colors cursor-pointer ${
              activeFilter === 'HOMOGLYPH'
                ? 'bg-purple-600 text-white border-purple-600 font-semibold'
                : 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700'
            }`}
          >
            Homoglyph & Typosquat
          </button>

          <button
            onClick={() => setActiveFilter('DOM')}
            className={`px-3 py-1.5 rounded-lg border font-medium transition-colors cursor-pointer ${
              activeFilter === 'DOM'
                ? 'bg-amber-600 text-white border-amber-600 font-semibold'
                : 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700'
            }`}
          >
            DOM & Forms
          </button>

          <button
            onClick={() => setActiveFilter('NETWORK_OSINT')}
            className={`px-3 py-1.5 rounded-lg border font-medium transition-colors cursor-pointer ${
              activeFilter === 'NETWORK_OSINT'
                ? 'bg-emerald-600 text-white border-emerald-600 font-semibold'
                : 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700'
            }`}
          >
            OSINT & Network
          </button>

          <button
            onClick={() => setActiveFilter('THREAT_FEED')}
            className={`px-3 py-1.5 rounded-lg border font-medium transition-colors cursor-pointer ${
              activeFilter === 'THREAT_FEED'
                ? 'bg-rose-600 text-white border-rose-600 font-semibold'
                : 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700'
            }`}
          >
            Threat Intel
          </button>
        </div>
      </div>

      {/* Breakdown Items List */}
      <div className="divide-y divide-slate-800/80">
        {filteredIndicators.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-400">
            No indicators match the selected filter category.
          </div>
        ) : (
          filteredIndicators.map((ind) => {
            const isPassed = ind.passed;
            const isCritical = ind.severity === 'CRITICAL';
            const isHigh = ind.severity === 'HIGH';

            return (
              <div
                key={ind.id}
                className={`p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-3 transition-colors ${
                  !isPassed
                    ? isCritical
                      ? 'bg-rose-950/15 hover:bg-rose-950/25'
                      : isHigh
                      ? 'bg-amber-950/15 hover:bg-amber-950/25'
                      : 'bg-slate-950/40 hover:bg-slate-900/60'
                    : 'hover:bg-slate-900/40'
                }`}
              >
                <div className="flex items-start gap-3.5">
                  <div className="mt-0.5 shrink-0">
                    {isPassed ? (
                      <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                    ) : isCritical ? (
                      <XCircle className="h-5 w-5 text-rose-400" />
                    ) : (
                      <AlertTriangle className="h-5 w-5 text-amber-400" />
                    )}
                  </div>
                  <div>
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span className="text-sm font-semibold text-slate-100">
                        {ind.title}
                      </span>
                      {getModuleBadge(ind.module)}
                      <span
                        className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded font-bold ${
                          isCritical
                            ? 'text-rose-400 bg-rose-500/10'
                            : isHigh
                            ? 'text-amber-400 bg-amber-500/10'
                            : 'text-slate-400 bg-slate-800'
                        }`}
                      >
                        {ind.severity}
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed max-w-2xl">
                      {ind.description}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-4 shrink-0 pl-8 md:pl-0 justify-between md:justify-end">
                  <div className="text-right">
                    <span
                      className={`text-xs font-mono font-bold block ${
                        isPassed
                          ? 'text-emerald-400'
                          : ind.points >= 30
                          ? 'text-rose-400'
                          : 'text-amber-400'
                      }`}
                    >
                      {isPassed ? '0 pts (Clean)' : `+${ind.points} pts added`}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">
                      {isPassed ? 'Passed inspection' : 'Threat indicator'}
                    </span>
                  </div>

                  <span
                    className={`px-2.5 py-1 rounded text-[11px] font-mono font-bold uppercase tracking-wider ${
                      isPassed
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                        : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                    }`}
                  >
                    {isPassed ? 'PASSED' : 'FLAGGED'}
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
