import { useEffect, useState } from 'react'
import { api } from './api'
import type { ScanDetail } from './api'
import { ScanView } from './views/ScanView'
import { Overview } from './views/Overview'
import { Inventory } from './views/Inventory'
import { Simulator } from './views/Simulator'
import { Roadmap } from './views/Roadmap'
import { Probe } from './views/Probe'
import { Knowledge } from './views/Knowledge'

type Tab = 'scan' | 'overview' | 'inventory' | 'simulator' | 'roadmap' | 'probe' | 'kb'

const TABS: { id: Tab; label: string; needsScan?: boolean }[] = [
  { id: 'scan', label: 'Discovery' },
  { id: 'overview', label: 'Overview', needsScan: true },
  { id: 'inventory', label: 'Inventory', needsScan: true },
  { id: 'simulator', label: 'Mosca simulator', needsScan: true },
  { id: 'roadmap', label: 'Roadmap', needsScan: true },
  { id: 'probe', label: 'Live probe' },
  { id: 'kb', label: 'Knowledge base' },
]

export function App() {
  const [tab, setTab] = useState<Tab>('scan')
  const [detail, setDetail] = useState<ScanDetail | null>(null)
  const [invFilter, setInvFilter] = useState<Record<string, string>>({})
  const [health, setHealth] = useState<{ current_year: number; algorithms: number } | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    api.health().then(setHealth).catch(() => {})
    // Open the most recent scan so the console is never an empty shell.
    api.scans().then(r => { if (r.scans[0]) load(r.scans[0].scan_id, false) }).catch(() => {})
  }, [])

  async function load(id: string, jump = true) {
    setLoading(true)
    try {
      const d = await api.scan(id)
      setDetail(d)
      if (jump) setTab('overview')
    } finally {
      setLoading(false)
    }
  }

  const goInventory = (f: Record<string, string>) => { setInvFilter(f); setTab('inventory') }
  const types = detail ? Object.keys(detail.summary.by_type) : []

  return (
    <div className="shell">
      <nav className="nav">
        <div className="brand">
          <b>Quantum Atlas</b>
          <span>ECDAT</span>
        </div>
        <div className="tabs">
          {TABS.map(t => (
            <button key={t.id} className="tab" aria-current={tab === t.id}
                    disabled={t.needsScan && !detail}
                    onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </div>
        <div className="row grow" style={{ justifyContent: 'flex-end', gap: 12 }}>
          {loading && <div className="spin" />}
          {detail && (
            <span className="mono t4" style={{ fontSize: 10.5 }}>
              scan {detail.scan_id.slice(0, 8)} · {detail.summary.artifacts_found.toLocaleString()} artefacts
            </span>
          )}
          {health && (
            <span className="mono t4" style={{ fontSize: 10.5 }}>
              {health.algorithms} algorithms · year {health.current_year}
            </span>
          )}
        </div>
      </nav>

      <div className="body">
        {tab === 'scan' && <ScanView onDone={id => load(id)} onOpen={id => load(id)} />}
        {tab === 'overview' && detail && <Overview d={detail} onGoInventory={goInventory} />}
        {tab === 'inventory' && detail && (
          <Inventory scanId={detail.scan_id} initial={invFilter} types={types} />
        )}
        {tab === 'simulator' && detail && <Simulator d={detail} year={health?.current_year} />}
        {tab === 'roadmap' && detail && (
          <Roadmap d={detail} onGoInventory={goInventory} year={health?.current_year} />
        )}
        {tab === 'probe' && <Probe />}
        {tab === 'kb' && <Knowledge />}
      </div>
    </div>
  )
}
