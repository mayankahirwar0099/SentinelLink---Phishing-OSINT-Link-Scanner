import React from 'react';
import { Package, ShieldAlert, CreditCard, Film, Car, AlertTriangle, CheckCircle, Eye, ArrowRight } from 'lucide-react';

interface SmishingGuideProps {
  onTestSample: (url: string) => void;
}

export const SmishingGuide: React.FC<SmishingGuideProps> = ({ onTestSample }) => {
  const scamScenarios = [
    {
      icon: Package,
      title: 'Postal & Package Delivery Smishing',
      pretext: '"USPS: Your package 94001000 is on hold due to incomplete address. Pay $0.35 redelivery fee."',
      howItWorks:
        'Attackers send fake notifications claiming a package cannot be delivered. The link leads to a clone of the postal service website designed to steal credit card numbers under the guise of a small 30-cent fee.',
      redFlag: 'Official postal services do not require small credit card fees via unsolicited SMS to complete deliveries.',
      sampleLink: 'https://usps-redelivery-notice.top/track',
    },
    {
      icon: CreditCard,
      title: 'Banking & Fraud Alerts',
      pretext: '"CHASE: Did you authorize a $720 Zelle transfer to David? Reply NO or click to cancel: https://chase-security..."',
      howItWorks:
        'Tricks victims into panic. The link opens a replica login page to harvest your username, password, and two-factor authentication (2FA) SMS code in real time.',
      redFlag: 'Legitimate banks never include direct login links in unprompted fraud alert texts.',
      sampleLink: 'https://bankofamerica.com.login-verify-alert.click/auth',
    },
    {
      icon: Film,
      title: 'Streaming & Subscription Account Holds',
      pretext: '"Netflix: Your payment method failed and your streaming subscription is paused. Update billing now."',
      howItWorks:
        'Capitalizes on annoyance over losing access to movies. Captures credit card CVV and billing address.',
      redFlag: 'Look closely at the domain name: legitimate Netflix links always end in exactly ".netflix.com".',
      sampleLink: 'https://netflix-update-billing-profile.xyz/login',
    },
    {
      icon: Car,
      title: 'Highway Toll Violations (SunPass / EZPass)',
      pretext: '"Toll Authority: You have an unpaid toll invoice of $4.50. Late fees apply in 48 hours. Pay at https://toll-pay..."',
      howItWorks:
        'Widespread mass SMS campaigns targeting drivers with minor unpaid fees to harvest debit cards.',
      redFlag: 'Toll agencies mail physical invoices to registered vehicle addresses, not random cell numbers.',
      sampleLink: 'https://toll-violation-redelivery.xyz/pay',
    },
  ];

  return (
    <div className="space-y-8">
      {/* Section 1: Lead Banner */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 sm:p-8 backdrop-blur-sm">
        <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white mb-2">
          How to Spot Suspicious SMS & Email Links in 3 Seconds
        </h2>
        <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
          Phishing and smishing (SMS phishing) rely on artificial urgency, fear, or excitement to force you into clicking before checking. Learn the core telltale signs to protect yourself and your family.
        </p>

        {/* The Golden Rule */}
        <div className="mt-5 rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs sm:text-sm text-slate-200">
            <span className="font-bold text-amber-300 block mb-0.5">The Golden Defense Rule:</span>
            Never click links in unprompted messages. Instead, open your browser independently and type the official website address yourself (e.g. <span className="font-mono text-amber-200">usps.com</span>, <span className="font-mono text-amber-200">chase.com</span>, <span className="font-mono text-amber-200">netflix.com</span>).
          </div>
        </div>
      </div>

      {/* Section 2: Anatomy of a Deceptive URL */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 sm:p-8 backdrop-blur-sm">
        <h3 className="text-base font-bold text-slate-100 uppercase tracking-wider mb-4">
          Anatomy of a Deceptive Web Link
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
          <div className="rounded-lg border border-rose-900/60 bg-rose-950/20 p-5 space-y-3">
            <div className="flex items-center gap-2 font-bold text-rose-400 uppercase">
              <AlertTriangle className="h-4 w-4" />
              <span>Fake Phishing Link</span>
            </div>
            <div className="font-mono text-sm bg-slate-950 p-3 rounded border border-rose-900/50 break-all text-rose-200">
              https://<span className="text-slate-400">usps.com.</span><span className="text-amber-300 font-bold underline">parcel-redelivery.xyz</span>/track
            </div>
            <p className="text-slate-300 leading-relaxed">
              Attackers put the real brand name (<span className="font-mono text-slate-200">usps.com</span>) in the beginning, but the real destination is always what comes right before the slash: <span className="font-mono text-amber-300 font-bold">parcel-redelivery.xyz</span>.
            </p>
          </div>

          <div className="rounded-lg border border-emerald-900/60 bg-emerald-950/20 p-5 space-y-3">
            <div className="flex items-center gap-2 font-bold text-emerald-400 uppercase">
              <CheckCircle className="h-4 w-4" />
              <span>Legitimate Official Link</span>
            </div>
            <div className="font-mono text-sm bg-slate-950 p-3 rounded border border-emerald-900/50 break-all text-emerald-200">
              https://<span className="text-slate-400">tools.</span><span className="text-emerald-300 font-bold underline">usps.com</span>/go/TrackConfirm
            </div>
            <p className="text-slate-300 leading-relaxed">
              The apex domain directly preceding the path is the genuine brand address (<span className="font-mono text-emerald-300 font-bold">usps.com</span>). No extra hyphenated domains or weird extensions.
            </p>
          </div>
        </div>
      </div>

      {/* Section 3: The 4 Common Attack Vectors */}
      <div>
        <h3 className="text-base font-bold text-slate-100 uppercase tracking-wider mb-4">
          Common Pretexts in 2026 Scams
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {scamScenarios.map((scam, i) => {
            const Icon = scam.icon;
            return (
              <div
                key={i}
                className="flex flex-col justify-between rounded-xl border border-slate-800 bg-slate-900/50 p-5 hover:border-slate-700 transition-all"
              >
                <div>
                  <div className="flex items-center gap-3 mb-2.5">
                    <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
                      <Icon className="h-5 w-5" />
                    </div>
                    <h4 className="text-sm font-bold text-slate-100">{scam.title}</h4>
                  </div>

                  <div className="mb-3 rounded bg-slate-950/80 p-2.5 font-mono text-[11px] text-amber-200/90 border border-slate-800 italic">
                    {scam.pretext}
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed mb-3">
                    {scam.howItWorks}
                  </p>

                  <div className="text-xs text-slate-400 border-t border-slate-800/80 pt-2 mb-3">
                    <span className="font-semibold text-rose-400">Tell:</span> {scam.redFlag}
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => onTestSample(scam.sampleLink)}
                  className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs font-semibold text-slate-300 hover:text-amber-400 hover:border-slate-700 transition-colors"
                >
                  <span>Test This Scam in Scanner</span>
                  <ArrowRight className="h-3.5 w-3.5 text-amber-400" />
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
