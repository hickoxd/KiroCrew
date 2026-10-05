import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Provider } from 'react-redux'
import { createTestStore } from './helpers'
import type { UsageSeriesPayload } from '../api/client'
import {
  TokenStackedAreaChart,
  nearestIndex,
  stackPaths,
  toCumulative,
} from '../pages/overview/TokenStackedAreaChart'

const { usageSeries } = vi.hoisted(() => ({ usageSeries: vi.fn() }))

vi.mock('../api/client', () => ({ api: { usageSeries } }))
// The chart colours its layers from the session palette, which reads the theme
// context; a fixed palette keeps the test on the chart's own behaviour.
vi.mock('../hooks/useSessionPalette', () => ({
  useSessionPalette: () => ({ paletteColors: ['#ff0000', '#00ff00', '#0000ff'] }),
}))

function payload(overrides: Partial<UsageSeriesPayload> = {}): UsageSeriesPayload {
  return {
    by: 'surface',
    metric: 'credits',
    days: 3,
    dates: ['2026-09-30', '2026-10-01', '2026-10-02'],
    series: [
      { key: 'dashboard', kind: 'bucket', values: [5, 0, 10], total: 15 },
      { key: 'cron', kind: 'bucket', values: [1, 1, 1], total: 3 },
      { key: '__other__', kind: 'other', values: [0, 2, 0], total: 2, members: 4 },
      { key: '__unattributed__', kind: 'unattributed', values: [0, 0, 0.5], total: 0.5 },
    ],
    total: 20.5,
    rows: 9,
    ...overrides,
  }
}

describe('toCumulative', () => {
  it('prefix-sums every layer and keeps the window total', () => {
    const [a, b] = toCumulative(payload().series)

    expect(a.values).toEqual([5, 5, 15])
    expect(b.values).toEqual([1, 2, 3])
    expect(a.total).toBe(15)
  })
})

describe('nearestIndex', () => {
  it('maps a pointer fraction onto the nearest day and clamps the edges', () => {
    expect(nearestIndex(0, 30)).toBe(0)
    expect(nearestIndex(1, 30)).toBe(29)
    expect(nearestIndex(0.5, 31)).toBe(15)
    expect(nearestIndex(-2, 30)).toBe(0)
    expect(nearestIndex(7, 30)).toBe(29)
    expect(nearestIndex(0.9, 1)).toBe(0)
  })
})

describe('stackPaths', () => {
  it('stacks bottom-first so the top edge is the day total', () => {
    const { paths, top } = stackPaths(payload().series, 3)

    expect(paths).toHaveLength(4)
    expect(paths.every(p => p.startsWith('M'))).toBe(true)
    // Day 3: 10 + 1 + 0 + 0.5 is the tallest column.
    expect(top).toBe(11.5)
  })

  it('never divides by zero on an all-zero window', () => {
    const empty = payload().series.map(s => ({ ...s, values: [0, 0, 0] }))

    expect(() => stackPaths(empty, 3)).not.toThrow()
  })
})

let client: QueryClient

function mount() {
  return render(
    <QueryClientProvider client={client}>
      <Provider store={createTestStore()}>
        <TokenStackedAreaChart />
      </Provider>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  localStorage.clear()
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  usageSeries.mockReset().mockResolvedValue(payload())
})
afterEach(() => {
  cleanup()
  client.clear()
})

describe('TokenStackedAreaChart', () => {
  it('requests the default view and draws one path per layer with a legend', async () => {
    mount()

    await screen.findByTestId('usage-series-chart')

    expect(usageSeries).toHaveBeenCalledWith('surface', 'credits')
    expect(document.querySelectorAll('path[data-layer]')).toHaveLength(4)
    const legend = screen.getByTestId('usage-series-legend')
    expect(legend).toHaveTextContent('dashboard')
    expect(legend).toHaveTextContent('cron')
    expect(legend).toHaveTextContent('Other (4 more)')
    expect(legend).toHaveTextContent('Unattributed')
    expect(legend.querySelector('[title]')).toHaveAttribute('title', 'Rows recorded before Crew tracked this field.')
  })

  it('names session-start-week layers by when their sessions were first seen, with a caption', async () => {
    usageSeries.mockResolvedValue(payload({
      by: 'cohort',
      series: [{ key: '2026-09-28', kind: 'bucket', values: [1, 1, 1], total: 3 }],
      total: 3,
    }))
    localStorage.setItem('kc.usageSeries.v1', JSON.stringify({ by: 'cohort', cumulative: true }))

    mount()

    await screen.findByTestId('usage-series-legend')
    expect(usageSeries).toHaveBeenCalledWith('cohort', 'credits')
    expect(screen.getByTestId('usage-series-legend')).toHaveTextContent('First seen week of Sep 28')
    expect(screen.getByTestId('usage-series-cohort-caption')).toHaveTextContent(/first seen in that week/)
  })

  it('shows no cohort caption for the other dimensions', async () => {
    mount()

    await screen.findByTestId('usage-series-chart')
    expect(screen.queryByTestId('usage-series-cohort-caption')).toBeNull()
  })

  it('persists the cumulative switch and re-stacks without refetching', async () => {
    mount()
    await screen.findByTestId('usage-series-chart')
    const before = document.querySelector('path[data-layer="dashboard"]')?.getAttribute('d')

    fireEvent.click(screen.getByRole('switch', { name: 'Cumulative' }))

    await waitFor(() => {
      expect(document.querySelector('path[data-layer="dashboard"]')?.getAttribute('d')).not.toBe(before)
    })
    expect(usageSeries).toHaveBeenCalledTimes(1)
    expect(JSON.parse(localStorage.getItem('kc.usageSeries.v1') ?? '{}')).toMatchObject({ cumulative: false })
  })

  it('shows the hovered day and its layers in a tooltip', async () => {
    mount()
    await screen.findByTestId('usage-series-chart')
    const plot = screen.getByTestId('usage-series-plot')
    plot.getBoundingClientRect = () => ({ left: 0, width: 300, top: 0, height: 100, right: 300, bottom: 100, x: 0, y: 0, toJSON: () => ({}) })

    fireEvent.pointerMove(plot, { clientX: 299 })

    const tip = await screen.findByRole('status')
    expect(tip).toHaveTextContent('Oct 2, 2026')
    // Cumulative view: dashboard has spent 15 of 20.5 by the last day.
    expect(tip).toHaveTextContent('Total to date: 20.5')
    expect(tip).toHaveTextContent('dashboard')
  })

  it('says so when nothing was spent', async () => {
    usageSeries.mockResolvedValue(payload({ series: [], total: 0, rows: 0 }))

    mount()

    expect(await screen.findByText('No spend recorded yet.')).toBeInTheDocument()
    expect(screen.queryByTestId('usage-series-chart')).toBeNull()
  })

  it('renders the failure through ErrorNotice', async () => {
    usageSeries.mockRejectedValue(new Error('series unavailable'))

    mount()

    expect(await screen.findByText('series unavailable')).toBeInTheDocument()
  })
})
