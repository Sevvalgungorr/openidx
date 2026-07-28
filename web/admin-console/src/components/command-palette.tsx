import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, CornerDownLeft } from 'lucide-react'

import { useAuth } from '../lib/auth'
import { useAppStore } from '../lib/store'
import { roleLevel, ROLE_LEVELS } from '../lib/roles'
import {
  filterNavigation,
  flattenNavItems,
  scoreNavItem,
  type FlatNavItem,
  type ViewMode,
} from '../config/navigation'

/**
 * ⌘K / Ctrl-K command palette: jump to any page across the whole console by
 * typing its name, its domain, or any of its search keywords. With 100+ pages
 * spread over seven domains, the sidebar alone makes features hard to find;
 * this gives every role a single fast entry point. It reuses filterNavigation,
 * so it only ever offers pages the signed-in user is actually allowed to open.
 */
export function CommandPalette() {
  const { user } = useAuth()
  const { viewMode } = useAppStore()
  const navigate = useNavigate()

  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  const roles = user?.roles ?? []
  const level = roleLevel(roles)
  const effectiveViewMode: ViewMode = level >= ROLE_LEVELS.operator ? viewMode : 'admin'

  // Role-filtered, flattened page list — recomputed only when identity/lens change.
  const items = useMemo(
    () => flattenNavItems(filterNavigation({ roles, viewMode: effectiveViewMode })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [roles.join(','), effectiveViewMode]
  )

  const results = useMemo(() => {
    const q = query.trim().toLowerCase()
    const scored = items
      .map((item) => ({ item, score: scoreNavItem(item, q) }))
      .filter((r) => r.score > 0)
    scored.sort((a, b) => b.score - a.score || a.item.name.localeCompare(b.item.name))
    return scored.slice(0, 20).map((r) => r.item)
  }, [items, query])

  // Global ⌘K / Ctrl-K toggle. Reset state when opening (in the handler, not an
  // effect) so the palette always shows a fresh, empty query.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen((v) => {
          if (!v) {
            setQuery('')
            setActive(0)
          }
          return !v
        })
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // Focus the input once the dialog is on screen.
  useEffect(() => {
    if (!open) return
    const t = setTimeout(() => inputRef.current?.focus(), 0)
    return () => clearTimeout(t)
  }, [open])

  // Keep the highlighted row scrolled into view.
  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-index="${active}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [active])

  if (!open) return null

  const go = (item: FlatNavItem | undefined) => {
    if (!item) return
    setOpen(false)
    navigate(item.href)
  }

  const onInputKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActive((i) => Math.min(i + 1, results.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((i) => Math.max(i - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      go(results[active])
    } else if (e.key === 'Escape') {
      e.preventDefault()
      setOpen(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/40 pt-[12vh] px-4"
      onMouseDown={() => setOpen(false)}
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
    >
      <div
        className="w-full max-w-xl overflow-hidden rounded-xl bg-white shadow-2xl dark:bg-gray-900"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 border-b px-4">
          <Search className="h-4 w-4 shrink-0 text-gray-400" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setActive(0)
            }}
            onKeyDown={onInputKey}
            placeholder="Jump to a page… (type a name or keyword)"
            className="h-12 w-full bg-transparent text-sm outline-none placeholder:text-gray-400"
            aria-label="Search pages"
          />
          <kbd className="hidden rounded border px-1.5 py-0.5 text-[10px] text-gray-400 sm:inline">
            esc
          </kbd>
        </div>

        <div ref={listRef} className="max-h-[50vh] overflow-y-auto p-2">
          {results.length === 0 ? (
            <p className="px-3 py-8 text-center text-sm text-gray-400">No pages match “{query}”.</p>
          ) : (
            results.map((item, i) => {
              const Icon = item.icon
              return (
                <button
                  key={item.href}
                  data-index={i}
                  onMouseEnter={() => setActive(i)}
                  onClick={() => go(item)}
                  className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm ${
                    i === active ? 'bg-blue-50 text-blue-900 dark:bg-blue-950 dark:text-blue-100' : ''
                  }`}
                >
                  <Icon className="h-4 w-4 shrink-0 text-gray-400" />
                  <span className="flex-1 truncate">{item.name}</span>
                  <span className="text-xs text-gray-400">{item.domainLabel}</span>
                  {i === active && <CornerDownLeft className="h-3.5 w-3.5 text-gray-400" />}
                </button>
              )
            })
          )}
        </div>
      </div>
    </div>
  )
}
