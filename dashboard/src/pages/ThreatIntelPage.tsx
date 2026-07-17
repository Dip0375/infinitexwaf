import { Shield, RefreshCw } from 'lucide-react';

export default function ThreatIntelPage() {
  return (
    <section className="space-y-6 p-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="text-sm uppercase tracking-[0.3em] text-cyan-400">Threat Intelligence</p>
          <h1 className="mt-2 text-3xl font-semibold text-white">Live feed and attack overview</h1>
          <p className="mt-3 max-w-2xl text-sm text-gray-400">
            Review the latest threat feed summaries, categories, and detection status for your WAF.
          </p>
        </div>

        <button
          type="button"
          className="inline-flex items-center gap-2 rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 shadow-lg shadow-cyan-500/20 transition hover:bg-cyan-400"
          onClick={() => window.location.reload()}
        >
          <RefreshCw className="h-4 w-4" /> Refresh data
        </button>
      </div>

      <div className="rounded-3xl border border-white/10 bg-slate-950/70 p-6 shadow-xl shadow-black/20">
        <div className="flex items-center gap-3 text-cyan-300">
          <Shield className="h-6 w-6" />
          <span className="text-sm font-medium">Real-time threat feed placeholder</span>
        </div>
        <div className="mt-4 text-sm text-gray-400">
          This page is currently a lightweight placeholder to keep the dashboard build working.
          The full threat intelligence panel can be implemented later with feed charts, severity metrics, and rule details.
        </div>
      </div>
    </section>
  );
}
