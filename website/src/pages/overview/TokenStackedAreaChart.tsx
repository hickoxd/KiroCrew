import { useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import { area, curveMonotoneX, stack } from 'd3'
import type { Series, SeriesPoint } from 'd3'
import { api } from '../../api/client'
import type {
  UsageSeriesDimension,
  UsageSeriesLayer,
  UsageSeriesPayload,
} from '../../api/client'
import ErrorNotice from '../../components/ErrorNotice'
import SimpleSelect from '../../components/SimpleSelect'
import { Toggle } from '../../components/ui'
import { useSessionPalette } from '../../hooks/useSessionPalette'
import { fmtCompact, fmtCredits, fmtDate, fmtDateFields, fmtNumber } from '../../i18n/format'
import { i18nT } from '../../i18n/t'
import { safeGetItem, safeSetItem } from '../../utils/safeStorage'

export const DIMENSIONS: UsageSeriesDimension[] = ['surface', 'agent', 'model', 'cohort']

// Flat tables indexed inline at the call, the one shape the static key checker
// can verify (see MemoryGraphTab's GROUP_LABEL_KEY).
const DIMENSION_LABEL_KEY: Record<UsageSeriesDimension, string> = {
  surface: 'pages.overview.usageSeriesChart.by_surface',
  agent: 'pages.overview.usageSeriesChart.by_agent',
  model: 'pages.overview.usageSeriesChart.by_model',
  cohort: 'pages.overview.usageSeriesChart.by_cohort',
}

/** Persisted view choices. Versioned so a shape change invalidates. */
const PREFS_KEY = 'kc.usageSeries.v1'
type Prefs = { by: UsageSeriesDimension; cumulative: boolean }
const DEFAULT_PREFS: Prefs = { by: 'surface', cumulative: true }

function readPrefs(): Prefs {
  try {
    const raw = safeGetItem(PREFS_KEY)
    if (!raw) return DEFAULT_PREFS
    const parsed = JSON.parse(raw) as Partial<Prefs>
    return {
      by: DIMENSIONS.includes(parsed.by as UsageSeriesDimension) ? (parsed.by as UsageSeriesDimension) : DEFAULT_PREFS.by,
      cumulative: typeof parsed.cumulative === 'boolean' ? parsed.cumulative : DEFAULT_PREFS.cumulative,
    }
  } catch {
    return DEFAULT_PREFS
  }
}

/** Running total per layer, so a layer that stopped spending stays level
 *  rather than vanishing: credits are never un-spent, which is what makes the
 *  cumulative stack the faithful reading of "what today's total is made of". */
export function toCumulative(layers: UsageSeriesLayer[]): UsageSeriesLayer[] {
  return layers.map(layer => {
    let running = 0
    return { ...layer, values: layer.values.map(v => (running += v)) }
  })
}

/** The day index under a pointer at `fraction` (0..1) of the chart width. */
export function nearestIndex(fraction: number, count: number): number {
  if (count <= 1) return 0
  const clamped = Math.min(1, Math.max(0, fraction))
  return Math.round(clamped * (count - 1))
}

/** `YYYY-MM-DD` as a LOCAL calendar day. `new Date('2026-09-14')` would read
 *  the string as UTC midnight and render the previous evening west of it. */
function localDay(iso: string): Date {
  const [y, m, d] = iso.split('-').map(Number)
  return new Date(y, m - 1, d)
}

type Row = Record<string, number>

/** Normalised chart space: paths are drawn in a 0..1000 box the SVG stretches. */
const BOX = 1000

export function stackPaths(layers: UsageSeriesLayer[], days: number): { paths: string[]; top: number } {
  const rows: Row[] = Array.from({ length: days }, (_, i) =>
    Object.fromEntries(layers.map(layer => [layer.key, layer.values[i] ?? 0])),
  )
  const stacked: Series<Row, string>[] = stack<Row>().keys(layers.map(layer => layer.key))(rows)
  const top = Math.max(1e-9, ...stacked.flatMap(series => series.map(point => point[1])))
  const x = (i: number) => (days <= 1 ? BOX / 2 : (i / (days - 1)) * BOX)
  const y = (v: number) => BOX - (v / top) * BOX
  const shape = area<SeriesPoint<Row>>()
    .x((_, i) => x(i))
    .y0(point => y(point[0]))
    .y1(point => y(point[1]))
    .curve(curveMonotoneX)
  return { paths: stacked.map(series => shape(series) ?? ''), top }
}

function layerLabel(layer: UsageSeriesLayer, by: UsageSeriesDimension): string {
  if (layer.kind === 'other') return i18nT('pages.overview.usageSeriesChart.other', { n: fmtNumber(layer.members ?? 0) })
  if (layer.kind === 'unattributed') return i18nT('pages.overview.usageSeriesChart.unattributed')
  if (by === 'cohort') return i18nT('pages.overview.usageSeriesChart.cohort_week', { date: fmtDateFields(localDay(layer.key), { month: 'short', day: 'numeric' }) })
  return layer.key
}

/**
 * Stacked area chart of spend over the shard retention window: one layer per
 * bucket of the chosen dimension, cumulative by default so the stack's top
 * edge is the window's
 * running total and each band's height is that bucket's share of it. The
 * per-day view is the same stack without the prefix sum. Layers come from the
 * backend already in stack order and already folded to top-N + other +
 * unattributed; the browser only sums, stacks and draws.
 */
export function TokenStackedAreaChart() {
  const [prefs, setPrefs] = useState<Prefs>(readPrefs)
  const [hover, setHover] = useState<number | null>(null)
  const plotRef = useRef<HTMLDivElement>(null)
  const reducedMotion = useReducedMotion()
  const { paletteColors } = useSessionPalette()

  const update = (patch: Partial<Prefs>) => {
    setPrefs(prev => {
      const next = { ...prev, ...patch }
      safeSetItem(PREFS_KEY, JSON.stringify(next))
      return next
    })
  }

  const { data, error: queryErr } = useQuery<UsageSeriesPayload>({
    queryKey: ['usage-series', prefs.by],
    queryFn: () => api.usageSeries(prefs.by, 'credits'),
    staleTime: 60_000,
  })
  const err = queryErr ? (queryErr instanceof Error ? queryErr.message : String(queryErr)) : ''

  const layers = useMemo(() => {
    if (!data) return []
    return prefs.cumulative ? toCumulative(data.series) : data.series
  }, [data, prefs.cumulative])
  const days = data?.dates.length ?? 0
  const { paths, top } = useMemo(() => stackPaths(layers, days), [layers, days])

  const colorOf = (layer: UsageSeriesLayer, index: number): string => {
    if (layer.kind === 'other') return 'var(--muted)'
    if (layer.kind === 'unattributed') return 'var(--muted-strong)'
    return paletteColors[index % paletteColors.length] || 'var(--accent)'
  }

  const pointTo = (clientX: number) => {
    const el = plotRef.current
    if (!el || days === 0) return
    const rect = el.getBoundingClientRect()
    if (rect.width <= 0) return
    setHover(nearestIndex((clientX - rect.left) / rect.width, days))
  }

  const controls = (
    <>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 mb-3 text-[12px] text-muted">
      <div className="flex items-center gap-2">
        <span>{i18nT('pages.overview.usageSeriesChart.layer_by')}</span>
        <SimpleSelect
          aria-label={i18nT('pages.overview.usageSeriesChart.layer_by')}
          options={DIMENSIONS}
          optionLabels={DIMENSIONS.map(d => i18nT(DIMENSION_LABEL_KEY[d]))}
          value={prefs.by}
          onChange={v => update({ by: v as UsageSeriesDimension })}
        />
      </div>
      <div className="flex items-center gap-2">
        <span>{i18nT('pages.overview.usageSeriesChart.cumulative')}</span>
        <Toggle
          checked={prefs.cumulative}
          onChange={v => update({ cumulative: v })}
          label={i18nT('pages.overview.usageSeriesChart.cumulative')}
        />
      </div>
      </div>
      {prefs.by === 'cohort' && (
        <p className="text-[12px] text-muted -mt-1 mb-3" data-testid="usage-series-cohort-caption">
          {i18nT('pages.overview.usageSeriesChart.cohort_caption')}
        </p>
      )}
    </>
  )

  if (err && !data) return <div>{controls}<ErrorNotice message={err} askAgent /></div>
  if (!data) return <div>{controls}<div className="skeleton h-44 rounded" /></div>
  if (data.total <= 0 || days === 0) {
    return (
      <div>
        {controls}
        <div className="text-[13px] text-muted py-6 text-center" data-testid="usage-series-empty">
          {i18nT('pages.overview.usageSeriesChart.empty')}
        </div>
      </div>
    )
  }

  const hoverX = hover == null ? null : days <= 1 ? 50 : (hover / (days - 1)) * 100
  // Bottom of the stack first, matching the legend: the largest bucket (or the
  // oldest cohort) leads, and the reserved layers close the list.
  const hoverRows = hover == null
    ? []
    : layers
        .map((layer, i) => ({ layer, i, value: layer.values[hover] ?? 0 }))
        .filter(r => r.value > 0)
  const hoverTotal = hoverRows.reduce((sum, r) => sum + r.value, 0)
  const transition = reducedMotion ? { duration: 0 } : { duration: 0.35, ease: 'easeOut' as const }

  return (
    <div data-testid="usage-series-chart">
      {err && <ErrorNotice title={i18nT('pages.sessionsTab.could_not_refresh')} message={err} askAgent className="mb-3" />}
      {controls}
      <div className="flex gap-2">
        {/* Y axis: HTML labels so the stretched SVG never distorts text. */}
        <div className="relative w-10 shrink-0 h-44 text-[10px] text-muted tabular-nums text-right">
          <span className="absolute right-0 top-0 leading-none">{fmtCompact(top)}</span>
          <span className="absolute right-0 top-1/2 -translate-y-1/2 leading-none">{fmtCompact(top / 2)}</span>
          <span className="absolute right-0 bottom-0 leading-none">{fmtNumber(0)}</span>
        </div>
        <div
          ref={plotRef}
          data-testid="usage-series-plot"
          className="relative flex-1 h-44 touch-none"
          onPointerMove={e => pointTo(e.clientX)}
          onPointerDown={e => pointTo(e.clientX)}
          onPointerLeave={() => setHover(null)}
        >
          <svg
            className="absolute inset-0 w-full h-full overflow-visible"
            viewBox={`0 0 ${BOX} ${BOX}`}
            preserveAspectRatio="none"
            role="img"
            aria-label={i18nT('pages.overview.usageSeriesChart.aria_label')}
          >
            {[0.25, 0.5, 0.75].map(f => (
              <line key={f} x1={0} x2={BOX} y1={BOX * f} y2={BOX * f} stroke="var(--border)" strokeDasharray="4 6" vectorEffect="non-scaling-stroke" />
            ))}
            <AnimatePresence initial={false}>
              {layers.map((layer, i) => (
                <motion.path
                  key={layer.key}
                  data-layer={layer.key}
                  // A layer that mounts mid-session (the dimension changed) must start at its
                  // real path: with no initial `d`, Framer animates from the absent attribute and
                  // writes d="undefined" for a frame, which the browser logs as an invalid path.
                  initial={{ opacity: 0, d: paths[i] }}
                  animate={{ opacity: 0.9, d: paths[i] }}
                  exit={{ opacity: 0 }}
                  transition={transition}
                  fill={colorOf(layer, i)}
                  stroke="var(--card)"
                  strokeWidth={1}
                  vectorEffect="non-scaling-stroke"
                />
              ))}
            </AnimatePresence>
            {hoverX != null && (
              <line x1={(hoverX / 100) * BOX} x2={(hoverX / 100) * BOX} y1={0} y2={BOX} stroke="var(--text)" strokeOpacity={0.5} vectorEffect="non-scaling-stroke" />
            )}
          </svg>
          {/* Tooltip sits INSIDE the plot (same choice as TokenDailyChart): hung
              above it, it would overflow the card for the top of the window. */}
          {hover != null && hoverX != null && (
            <div
              role="status"
              className="absolute top-1 -translate-x-1/2 bg-bg-elevated border border-border rounded px-2 py-1 text-[11px] whitespace-nowrap z-50 shadow-lg pointer-events-none"
              style={{ left: `clamp(5rem, ${hoverX}%, calc(100% - 5rem))` }}
            >
              <div className="font-medium">{fmtDate(localDay(data.dates[hover]))}</div>
              <div className="text-muted">
                {i18nT(prefs.cumulative ? 'pages.overview.usageSeriesChart.total_to_date' : 'pages.overview.usageSeriesChart.total_that_day', { value: fmtCredits(hoverTotal) })}
              </div>
              {hoverRows.slice(0, 8).map(({ layer, i, value }) => (
                <div key={layer.key} className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-sm inline-block shrink-0" style={{ background: colorOf(layer, i) }} />
                  <span className="truncate max-w-56">{layerLabel(layer, prefs.by)}</span>
                  <span className="ml-auto pl-3 tabular-nums">{fmtCredits(value)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
      <div className="flex justify-between pl-12 mt-1 text-[10px] text-muted">
        {[...new Set([0, Math.floor((days - 1) / 2), days - 1])].map(i => (
          <span key={i}>{fmtDateFields(localDay(data.dates[i]), { month: 'short', day: 'numeric' })}</span>
        ))}
      </div>
      <div data-testid="usage-series-legend" className="flex gap-x-4 gap-y-1 mt-3 text-[12px] text-muted justify-center flex-wrap">
        {layers.map((layer, i) => (
          <span key={layer.key} className="flex items-center gap-1.5" title={layer.kind === 'unattributed' ? i18nT('pages.overview.usageSeriesChart.unattributed_hint') : undefined}>
            <span className="w-3 h-3 rounded-sm inline-block shrink-0" style={{ background: colorOf(layer, i) }} />
            <span className="truncate max-w-64">{layerLabel(layer, prefs.by)}</span>
            <span className="tabular-nums">{fmtCredits(layer.total)}</span>
          </span>
        ))}
      </div>
    </div>
  )
}
