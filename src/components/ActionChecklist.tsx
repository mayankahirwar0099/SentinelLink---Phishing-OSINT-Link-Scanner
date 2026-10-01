import React, { useState } from 'react';
import { CheckSquare, Square, AlertCircle, PhoneOff, Trash2, KeyRound, ExternalLink } from 'lucide-react';
import type { ScanResult } from '../types/scanner.js';

interface ActionChecklistProps {
  result: ScanResult;
}

export const ActionChecklist: React.FC<ActionChecklistProps> = ({ result }) => {
  const { aiAnalysis, brandCheck, riskLevel } = result;
  const isHighRisk = riskLevel === 'HIGH_RISK';
  const isSuspicious = riskLevel === 'SUSPICIOUS';

  const defaultActions = aiAnalysis.recommendedActions.length > 0
    ? aiAnalysis.recommendedActions
    : isHighRisk
    ? [
        'Do not tap or open this link on any device.',
        'Delete the SMS or email message immediately.',
        'Block the sender phone number or email address on your device.',
        'If you already entered your password, change it immediately on the official service website.',
        'If you entered credit card details, call your bank card issuer to freeze the card.',
      ]
    : isSuspicious
    ? [
        'Do not enter login credentials or payment information.',
        'Verify the authenticity of the message with the sender through a known, trusted phone number.',
        'Check your account directly by navigating to the official website in a fresh tab.',
      ]
    : [
        'Ensure the URL in your browser matches the expected domain name.',
        'Verify that the website uses an active HTTPS padlock connection.',
      ];

  const [checkedItems, setCheckedItems] = useState<Record<number, boolean>>({});

  const toggleCheck = (idx: number) => {
    setCheckedItems((prev) => ({
      ...prev,
      [idx]: !prev[idx],
    }));
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 sm:p-6 backdrop-blur-sm">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
        <div className="flex items-center gap-2">
          <AlertCircle className={`h-4 w-4 ${isHighRisk ? 'text-rose-400' : 'text-amber-400'}`} />
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wide">
            Immediate Action Checklist
          </h3>
        </div>
        <span className="text-xs text-slate-400 font-mono">
          {Object.values(checkedItems).filter(Boolean).length} of {defaultActions.length} completed
        </span>
      </div>

      <p className="text-xs text-slate-300 mb-4">
        Follow these step-by-step precautions to secure your device and protect your personal data from unauthorized access:
      </p>

      <div className="space-y-2.5">
        {defaultActions.map((action, idx) => {
          const isChecked = !!checkedItems[idx];
          return (
            <div
              key={idx}
              onClick={() => toggleCheck(idx)}
              className={`flex items-start gap-3 rounded-lg border p-3 cursor-pointer transition-colors ${
                isChecked
                  ? 'border-emerald-500/30 bg-emerald-950/10 text-slate-400 line-through'
                  : 'border-slate-800 bg-slate-950/60 hover:border-slate-700 text-slate-200'
              }`}
            >
              <button
                type="button"
                className="mt-0.5 text-slate-400 hover:text-amber-400 focus:outline-none"
              >
                {isChecked ? (
                  <CheckSquare className="h-4 w-4 text-emerald-400" />
                ) : (
                  <Square className="h-4 w-4 text-slate-500" />
                )}
              </button>
              <span className="text-xs sm:text-sm font-medium leading-relaxed">
                {action}
              </span>
            </div>
          );
        })}
      </div>

      {brandCheck.isImpersonating && brandCheck.officialDomain && (
        <div className="mt-5 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3.5 flex items-start justify-between gap-3 text-xs">
          <div>
            <span className="font-semibold text-amber-300 block mb-0.5">
              Official {brandCheck.targetedBrand} Portal
            </span>
            <span className="text-slate-400">
              Need to check an actual parcel, account alert, or billing update? Visit the official website directly:
            </span>
          </div>
          <a
            href={`https://${brandCheck.officialDomain}`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 shrink-0 rounded bg-slate-800 px-2.5 py-1.5 font-mono text-amber-300 hover:bg-slate-700 transition-colors"
          >
            <span>{brandCheck.officialDomain}</span>
            <ExternalLink className="h-3 w-3" />
          </a>
        </div>
      )}
    </div>
  );
};
