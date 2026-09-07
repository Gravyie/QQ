import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Radar, LayoutDashboard, Server, Database, ShieldCheck, Zap,
  Sliders, Milestone, Radio, BookOpen, ArrowLeft
} from 'lucide-react'
import { api } from './api'
import type { ScanDetail } from './api'
import { ScanView } from './views/ScanView'
import { Overview } from './views/Overview'
import { Services } from './views/Services'
import { Inventory } from './views/Inventory'
import { Compliance } from './views/Compliance'
import { Alternatives } from './views/Alternatives'
import { Simulator } from './views/Simulator'
import { Roadmap } from './views/Roadmap'
import { Probe } from './views/Probe'
import { Knowledge } from './views/Knowledge'

type Tab =
  | 'scan'
  | 'overview'
  | 'services'
  | 'inventory'
  | 'compliance'
  | 'alternatives'
  | 'simulator'
  | 'roadmap'
  | 'probe'
  | 'kb'

const TABS: { id: Tab; label: string; icon: any; needsScan?: boolean }[] = [
  { id: 'scan', label: 'Discovery', icon: Radar },
  { id: 'overview', label: 'Overview', icon: LayoutDashboard, needsScan: true },
  { id: 'services', label: 'Services', icon: Server, needsScan: true },
  { id: 'inventory', label: 'Inventory', icon: Database, needsScan: true },
  { id: 'compliance', label: 'Compliance', icon: ShieldCheck, needsScan: true },
  { id: 'alternatives', label: 'Alternatives', icon: Zap, needsScan: true },
  { id: 'simulator', label: 'Simulator', icon: Sliders, needsScan: true },
  { id: 'roadmap', label: 'Roadmap', icon: Milestone, needsScan: true },
  { id: 'probe', label: 'Probe', icon: Radio },
  { id: 'kb', label: 'Knowledge Base', icon: BookOpen },
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
        <div className="nav-left">
          <div
            className="brand"
            onClick={() => { window.location.hash = '#' }}
            title="Back to Landing Page"
          >
            <svg width="18" height="18" viewBox="0 0 20 20" fill="none" aria-hidden="true" style={{ filter: 'drop-shadow(0 0 6px rgba(0,240,255,0.6))' }}>
              <path d="M10 1.6 18 6v8l-8 4.4L2 14V6l8-4.4Z" stroke="var(--cyan)" strokeWidth="1.3" opacity="0.9" />
              <path d="M10 6.2 14 8.4v4.2L10 14.8 6 12.6V8.4l4-2.2Z" stroke="var(--accent)" strokeWidth="1.1" opacity="0.8" />
              <circle cx="10" cy="10.5" r="1.8" fill="var(--cyan)" />
            </svg>
            <b>Quantum Atlas</b>
            <span>ECDAT</span>
          </div>
        </div>

        <div className="tabs" style={{ paddingBottom: 2 }}>
          {TABS.map(t => {
            const Icon = t.icon
            const active = tab === t.id
            return (
              <button
                key={t.id}
                className="tab"
                aria-current={active}
                disabled={t.needsScan && !detail}
                onClick={() => setTab(t.id)}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 5,
                  padding: '5px 8px',
                  whiteSpace: 'nowrap',
                  flexShrink: 0,
                  fontSize: 12,
                }}
              >
                <Icon size={13} style={{ color: active ? 'var(--cyan)' : 'var(--t3)' }} />
                <span>{t.label}</span>
                {active && (
                  <motion.div
                    layoutId="activeTabPill"
                    style={{
                      position: 'absolute',
                      inset: 0,
                      borderRadius: 6,
                      background: 'rgba(255, 255, 255, 0.05)',
                      border: '1px solid var(--accent-line)',
                      boxShadow: '0 0 12px rgba(94, 106, 210, 0.25)',
                      pointerEvents: 'none',
                    }}
                    transition={{ type: 'spring', stiffness: 450, damping: 35 }}
                  />
                )}
              </button>
            )
          })}
        </div>

        <div className="nav-right">
          {loading && <div className="spin" />}
          {detail && (
            <span
              className="nav-badge"
              title={`Scan ID: ${detail.scan_id}`}
            >
              <span className="nav-badge-dot" />
              <span>{detail.summary.artifacts_found.toLocaleString()} artefacts</span>
            </span>
          )}
          <a
            href="#"
            className="nav-back-btn"
            title="Return to Presentation Landing Page"
          >
            <ArrowLeft size={12} />
            <span>Landing</span>
          </a>
        </div>
      </nav>

      <div className="body">
        <AnimatePresence mode="wait">
          <motion.div
            key={tab}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.2, ease: [0.25, 0.9, 0.35, 1] }}
          >
            {tab === 'scan' && <ScanView onDone={id => load(id)} onOpen={id => load(id)} />}
            {tab === 'overview' && detail && <Overview d={detail} onGoInventory={goInventory} />}
            {tab === 'services' && detail && <Services d={detail} onGoInventory={goInventory} />}
            {tab === 'inventory' && detail && (
              <Inventory scanId={detail.scan_id} initial={invFilter} types={types} />
            )}
            {tab === 'compliance' && detail && (
              <Compliance d={detail} onGoInventory={goInventory} />
            )}
            {tab === 'alternatives' && detail && (
              <Alternatives d={detail} onGoInventory={goInventory} />
            )}
            {tab === 'simulator' && detail && <Simulator d={detail} year={health?.current_year} />}
            {tab === 'roadmap' && detail && (
              <Roadmap d={detail} onGoInventory={goInventory} year={health?.current_year} />
            )}
            {tab === 'probe' && <Probe />}
            {tab === 'kb' && <Knowledge />}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  )
}
