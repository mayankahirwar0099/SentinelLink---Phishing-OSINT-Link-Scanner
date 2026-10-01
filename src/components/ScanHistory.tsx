import React from 'react';
import { History, Trash2, ArrowUpRight, ShieldCheck, AlertOctagon, AlertTriangle, Clock } from 'lucide-react';
import type { ScanResult } from '../types/scanner.js';

interface ScanHistoryProps {
  history: ScanResult[];
  onSelectScan: (scan: ScanResult) => void;
  onClearHistory: () => void;
  onRemoveScan: (id: string) => void;
}

export const ScanHistory: React.FC<ScanHistoryProps> = ({
  history,
  onSelectScan,
  onClearHistory,
  onRemoveScan,
}) => {
  if (history.length === 0) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-8 text-center backdrop-blur-sm">
        <History className="h-10 w-10 text-slate-600 mx-auto mb-3" />
        <h3 className="text-base font-bold text-slate-200">No Scan Records Yet</h3>
        <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
          Every link or message you submit for verification is safely saved here for reference.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 sm:p-6 backdrop-blur-sm">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
        <div>
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
            Local Scan Vault
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Previous security assessments performed on this device.
          </p>
        </div>

        <button
          onClick={onClearHistory}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-rose-400 transition-colors"
        >
          <Trash2 className="h-3.5 w-3.5" />
          <span>Clear History</span>
        </button>
      </div>

      <div className="space-y-2.5">
        {history.map((scan) => {
          const isHigh = scan.riskLevel === 'HIGH_RISK';
          const isSuspicious = scan.riskLevel === 'SUSPICIOUS';
          const isSafe = scan.riskLevel === 'SAFE' || scan.riskLevel === 'LOW_RISK';

          return (
            <div
              key={scan.id}
              className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-lg border border-slate-800/80 bg-slate-950/60 p-3.5 hover:border-slate-700 transition-all text-xs"
            >
              <div
                className="flex-1 cursor-pointer"
                onClick={() => onSelectScan(scan)}
              >
                <div className="flex items-center gap-2 mb-1">
                  {isHigh ? (
                    <span className="flex items-center gap-1 text-[11px] font-mono font-bold text-rose-400 uppercase">
                      <AlertOctagon className="h-3.5 w-3.5" />
                      <span>High Risk ({scan.riskScore}/100)</span>
                    </span>
                  ) : isSuspicious ? (
                    <span className="flex items-center gap-1 text-[11px] font-mono font-bold text-amber-400 uppercase">
                      <AlertTriangle className="h-3.5 w-3.5" />
                      <span>Suspicious ({scan.riskScore}/100)</span>
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-[11px] font-mono font-bold text-emerald-400 uppercase">
                      <ShieldCheck className="h-3.5 w-3.5" />
                      <span>Safe ({scan.riskScore}/100)</span>
                    </span>
                  )}
                  <span className="text-slate-600">·</span>
                  <span className="text-[11px] text-slate-500 font-mono">
                    {new Date(scan.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>

                <div className="font-mono text-slate-200 font-medium break-all">
                  {scan.targetDomain}
                </div>

                {scan.smsMessageContext && (
                  <p className="text-[11px] text-slate-400 line-clamp-1 italic mt-0.5">
                    "{scan.smsMessageContext}"
                  </p>
                )}
              </div>

              <div className="flex items-center gap-2 shrink-0 justify-end">
                <button
                  type="button"
                  onClick={() => onSelectScan(scan)}
                  className="flex items-center gap-1 rounded bg-slate-900 border border-slate-800 px-2.5 py-1 text-[11px] font-medium text-slate-300 hover:text-amber-300 hover:bg-slate-800 transition-colors"
                >
                  <span>View Details</span>
                  <ArrowUpRight className="h-3 w-3" />
                </button>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onRemoveScan(scan.id);
                  }}
                  className="p-1 text-slate-500 hover:text-rose-400 transition-colors"
                  title="Remove from history"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
