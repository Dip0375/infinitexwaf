import { createContext, useContext, useState, useCallback, ReactNode } from 'react';

export type RelativeUnit = 'minutes' | 'hours' | 'days' | 'months';

export interface AbsoluteRange {
  from: string; // ISO date string
  to: string;
}

export interface TimeRange {
  mode: 'relative' | 'absolute';
  // relative
  relativeValue?: number;
  relativeUnit?: RelativeUnit;
  relativePreset?: string; // e.g. '5m', '1h'
  // absolute
  absolute?: AbsoluteRange;
  // resolved
  from: Date;
  to: Date;
  label: string;
  apiRange: string; // what we send to /api/dashboard/timeseries
}

function resolveRelative(value: number, unit: RelativeUnit): { from: Date; to: Date; label: string; apiRange: string } {
  const to = new Date();
  const from = new Date(to);
  const label = `Last ${value} ${unit}`;

  switch (unit) {
    case 'minutes': from.setMinutes(from.getMinutes() - value); break;
    case 'hours':   from.setHours(from.getHours() - value);     break;
    case 'days':    from.setDate(from.getDate() - value);        break;
    case 'months':  from.setMonth(from.getMonth() - value);      break;
  }

  // Map to nearest API range
  const totalMinutes = (to.getTime() - from.getTime()) / 60000;
  let apiRange = '24h';
  if (totalMinutes <= 60)        apiRange = '1h';
  else if (totalMinutes <= 360)  apiRange = '6h';
  else if (totalMinutes <= 1440) apiRange = '24h';
  else if (totalMinutes <= 10080)apiRange = '7d';
  else                           apiRange = '30d';

  return { from, to, label, apiRange };
}

const PRESETS = [
  { label: '5m',   value: 5,   unit: 'minutes' as RelativeUnit },
  { label: '15m',  value: 15,  unit: 'minutes' as RelativeUnit },
  { label: '30m',  value: 30,  unit: 'minutes' as RelativeUnit },
  { label: '1h',   value: 1,   unit: 'hours'   as RelativeUnit },
  { label: '3h',   value: 3,   unit: 'hours'   as RelativeUnit },
  { label: '12h',  value: 12,  unit: 'hours'   as RelativeUnit },
  { label: '1d',   value: 1,   unit: 'days'    as RelativeUnit },
  { label: '2d',   value: 2,   unit: 'days'    as RelativeUnit },
  { label: '3d',   value: 3,   unit: 'days'    as RelativeUnit },
  { label: '5d',   value: 5,   unit: 'days'    as RelativeUnit },
];

export { PRESETS };

function buildDefault(): TimeRange {
  const { from, to, label, apiRange } = resolveRelative(24, 'hours');
  return {
    mode: 'relative', relativeValue: 24, relativeUnit: 'hours',
    relativePreset: '1d', from, to, label, apiRange,
  };
}

interface Ctx {
  range: TimeRange;
  setRelativePreset: (preset: typeof PRESETS[0]) => void;
  setCustomRelative: (value: number, unit: RelativeUnit) => void;
  setAbsolute: (from: string, to: string) => void;
}

const TimeRangeContext = createContext<Ctx | null>(null);

export function TimeRangeProvider({ children }: { children: ReactNode }) {
  const [range, setRange] = useState<TimeRange>(buildDefault);

  const setRelativePreset = useCallback((preset: typeof PRESETS[0]) => {
    const { from, to, label, apiRange } = resolveRelative(preset.value, preset.unit);
    setRange({ mode: 'relative', relativeValue: preset.value, relativeUnit: preset.unit,
      relativePreset: preset.label, from, to, label, apiRange });
  }, []);

  const setCustomRelative = useCallback((value: number, unit: RelativeUnit) => {
    const { from, to, label, apiRange } = resolveRelative(value, unit);
    setRange({ mode: 'relative', relativeValue: value, relativeUnit: unit,
      relativePreset: undefined, from, to, label, apiRange });
  }, []);

  const setAbsolute = useCallback((fromStr: string, toStr: string) => {
    const from = new Date(fromStr);
    const to   = new Date(toStr);
    const fmt = (d: Date) => d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    const totalMinutes = (to.getTime() - from.getTime()) / 60000;
    let apiRange = '24h';
    if (totalMinutes <= 60)        apiRange = '1h';
    else if (totalMinutes <= 360)  apiRange = '6h';
    else if (totalMinutes <= 1440) apiRange = '24h';
    else if (totalMinutes <= 10080)apiRange = '7d';
    else                           apiRange = '30d';
    setRange({ mode: 'absolute', absolute: { from: fromStr, to: toStr },
      from, to, label: `${fmt(from)} → ${fmt(to)}`, apiRange });
  }, []);

  return (
    <TimeRangeContext.Provider value={{ range, setRelativePreset, setCustomRelative, setAbsolute }}>
      {children}
    </TimeRangeContext.Provider>
  );
}

export function useTimeRange() {
  const ctx = useContext(TimeRangeContext);
  if (!ctx) throw new Error('useTimeRange must be used inside TimeRangeProvider');
  return ctx;
}
