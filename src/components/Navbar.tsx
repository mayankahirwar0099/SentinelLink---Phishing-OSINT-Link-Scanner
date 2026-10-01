import React from 'react';
import { ShieldAlert, Zap } from 'lucide-react';

interface NavbarProps {
  onQuickSampleClick: () => void;
  activeTab: 'scanner' | 'guide' | 'history';
  setActiveTab: (tab: 'scanner' | 'guide' | 'history') => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  onQuickSampleClick,
  activeTab,
  setActiveTab,
}) => {
  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-slate-950/85 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Zone 1: Brand Wordmark (Single text element) */}
        <div className="flex items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <button
            onClick={() => setActiveTab('scanner')}
            className="text-left text-lg font-bold tracking-tight text-white hover:text-amber-400 transition-colors"
          >
            SentinelLink
          </button>
        </div>

        {/* Zone 2: Navigation Links (Clean text links) */}
        <nav className="hidden md:flex items-center gap-8 text-sm font-medium">
          <button
            onClick={() => setActiveTab('scanner')}
            className={`transition-colors py-1 ${
              activeTab === 'scanner'
                ? 'text-amber-400 font-semibold border-b-2 border-amber-400'
                : 'text-slate-300 hover:text-white'
            }`}
          >
            Scanner Console
          </button>
          <button
            onClick={() => setActiveTab('guide')}
            className={`transition-colors py-1 ${
              activeTab === 'guide'
                ? 'text-amber-400 font-semibold border-b-2 border-amber-400'
                : 'text-slate-300 hover:text-white'
            }`}
          >
            Smishing & Phishing Guide
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`transition-colors py-1 ${
              activeTab === 'history'
                ? 'text-amber-400 font-semibold border-b-2 border-amber-400'
                : 'text-slate-300 hover:text-white'
            }`}
          >
            Scan Vault & History
          </button>
        </nav>

        {/* Zone 3: Primary Action */}
        <div className="flex items-center gap-3">
          <button
            onClick={onQuickSampleClick}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900/90 px-3.5 py-1.5 text-xs font-semibold text-slate-200 transition-all hover:border-amber-500/50 hover:bg-slate-800 hover:text-white"
          >
            <Zap className="h-3.5 w-3.5 text-amber-400" />
            <span>Load Scam Sample</span>
          </button>
        </div>
      </div>
    </header>
  );
};
