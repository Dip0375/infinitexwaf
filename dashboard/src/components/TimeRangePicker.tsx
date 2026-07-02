import { useState, useRef, useEffect } from 'react';
import { Calendar, Clock, ChevronDown, X, Check } from 'lucide-react';
import { useTimeRange, PRESETS, RelativeUnit } from '../context/TimeRangeContext';

const UNITS: RelativeUnit[] = ['minutes', 'hours', 'days', 'months'];

function pad(n: number) { return String(n).padStart(2, '0'); }

function toDatetimeLocal(d: Date) {
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function TimeRangePicker() {
  const { range, setRelativePreset, setCustomRelative, setAbsolute } = useTimeRange();
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<'relative' | 'absolute'>('relative');
  const [customVal, setCustomVal] = useState(24);
  const [customUnit, setCustomUnit] = useState<RelativeUnit>('hours');
  const [absFrom, setAbsFrom] = useState(() => toDatetimeLocal(new Date(Date.now() - 86400000)));
  const [absTo,   setAbsTo]   = useState(() => toDatetimeLocal(new Date()));
  const ref = useRef<HTMLDivElement>(null);

  // Close on outside click
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  function applyCustomRelative() {
    if (customVal > 0) { setCustomRelative(customVal, customUnit); setOpen(false); }
  }

  function applyAbsolute() {
    if (absFrom && absTo && absFrom < absTo) { setAbsolute(absFrom, absTo); setOpen(false); }
  }

  return (
    <div ref={ref} className="relative">
      {/* Trigger button */}
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-2 px-3 py-2 bg-gray-900/80 border border-gray-700 rounded-xl text-sm text-gray-300 hover:border-cyan-500/50 hover:text-white transition-all min-w-[180px]"
      >
        <Clock className="w-4 h-4 text-cyan-400 shrink-0" />
        <span className="flex-1 text-left truncate">{range.label}</span>
        <ChevronDown className={`w-4 h-4 text-gray-500 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {/* Dropdown panel */}
      {open && (
        <div className="absolute right-0 top-full mt-2 z-50 w-[420px] bg-gray-900 border border-gray-700 rounded-2xl shadow-2xl shadow-black/50 overflow-hidden">
          {/* Tab bar */}
          <div className="flex border-b border-gray-800">
            {(['relative', 'absolute'] as const).map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`flex-1 flex items-center justify-center gap-2 py-3 text-sm font-medium transition-colors ${
                  tab === t ? 'text-cyan-400 border-b-2 border-cyan-400 -mb-px' : 'text-gray-400 hover:text-white'
                }`}
              >
                {t === 'relative' ? <Clock className="w-4 h-4" /> : <Calendar className="w-4 h-4" />}
                {t === 'relative' ? 'Relative' : 'Absolute'}
              </button>
            ))}
          </div>

          {/* ── RELATIVE TAB ── */}
          {tab === 'relative' && (
            <div className="p-4 space-y-4">
              {/* Quick presets */}
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Quick Select</p>
                <div className="grid grid-cols-5 gap-1.5">
                  {PRESETS.map((p) => (
                    <button
                      key={p.label}
                      onClick={() => { setRelativePreset(p); setOpen(false); }}
                      className={`py-1.5 rounded-lg text-sm font-medium transition-all ${
                        range.mode === 'relative' && range.relativePreset === p.label
                          ? 'bg-cyan-500 text-white'
                          : 'bg-gray-800 text-gray-300 hover:bg-gray-700 hover:text-white'
                      }`}
                    >
                      {p.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Custom relative */}
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Custom</p>
                <div className="flex gap-2 items-center">
                  <span className="text-sm text-gray-400 shrink-0">Last</span>
                  <input
                    type="number"
                    min={1}
                    value={customVal}
                    onChange={(e) => setCustomVal(Math.max(1, +e.target.value))}
                    className="w-20 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white text-center focus:outline-none focus:border-cyan-500"
                  />
                  <select
                    value={customUnit}
                    onChange={(e) => setCustomUnit(e.target.value as RelativeUnit)}
                    className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  >
                    {UNITS.map((u) => <option key={u} value={u}>{u}</option>)}
                  </select>
                  <button
                    onClick={applyCustomRelative}
                    className="px-3 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-1"
                  >
                    <Check className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ── ABSOLUTE TAB ── */}
          {tab === 'absolute' && (
            <div className="p-4 space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-gray-500 block mb-1.5">From</label>
                  <input
                    type="datetime-local"
                    value={absFrom}
                    onChange={(e) => setAbsFrom(e.target.value)}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 [color-scheme:dark]"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-500 block mb-1.5">To</label>
                  <input
                    type="datetime-local"
                    value={absTo}
                    onChange={(e) => setAbsTo(e.target.value)}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 [color-scheme:dark]"
                  />
                </div>
              </div>

              {/* Time range slider hint */}
              <div className="bg-gray-800/50 rounded-xl p-3 text-xs text-gray-400 space-y-1">
                <p className="flex justify-between">
                  <span>From</span>
                  <span className="text-white">{absFrom ? new Date(absFrom).toLocaleString() : '—'}</span>
                </p>
                <p className="flex justify-between">
                  <span>To</span>
                  <span className="text-white">{absTo ? new Date(absTo).toLocaleString() : '—'}</span>
                </p>
                {absFrom && absTo && absFrom < absTo && (
                  <p className="flex justify-between text-cyan-400">
                    <span>Duration</span>
                    <span>{formatDuration(new Date(absFrom), new Date(absTo))}</span>
                  </p>
                )}
                {absFrom && absTo && absFrom >= absTo && (
                  <p className="text-red-400">End time must be after start time</p>
                )}
              </div>

              <button
                onClick={applyAbsolute}
                disabled={!absFrom || !absTo || absFrom >= absTo}
                className="w-full py-2 bg-cyan-500 hover:bg-cyan-600 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-xl text-sm font-medium transition-colors"
              >
                Apply Range
              </button>
            </div>
          )}

          {/* Footer — current selection */}
          <div className="px-4 py-3 border-t border-gray-800 flex items-center justify-between">
            <span className="text-xs text-gray-500">Current: <span className="text-cyan-400">{range.label}</span></span>
            <button onClick={() => setOpen(false)} className="text-gray-600 hover:text-white">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function formatDuration(from: Date, to: Date): string {
  const ms = to.getTime() - from.getTime();
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ${mins % 60}m`;
  const days = Math.floor(hrs / 24);
  return `${days}d ${hrs % 24}h`;
}
