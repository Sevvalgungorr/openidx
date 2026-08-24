import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { AlertTriangle } from 'lucide-react'
import { Button } from '../components/ui/button'
import { useGuacSessionPhase } from '../components/remote/guac-session-viewer'

/**
 * Standalone, chrome-less window that hosts ONE Apache Guacamole session.
 *
 * PAM launches want the old multi-window behaviour (each connection in its own
 * OS window / monitor) WITHOUT ever exposing Guacamole's own chrome. So the
 * console opens `window.open('/pam-session?k=<key>')` instead of the raw guac
 * URL, and hands the (token-bearing) connect URL off out-of-band via a
 * single-use localStorage entry — the token never touches the URL or history.
 *
 * On mount we read+immediately delete `pam-session:<key>` (single use). If it's
 * present we frame the guac client full-window and reuse the shared phase
 * monitor (`useGuacSessionPhase`): while the frame sits on a `#/client/...`
 * route the session is live; the moment it leaves (or never reaches) that
 * route we unmount the iframe and paint an OpenIDX card — the user only ever
 * sees OpenIDX messaging, never guac's home/connection-manager.
 *
 * If the handoff is missing/expired (double-open, reload, stale link) we show
 * an "expired" card telling the user to relaunch from the console.
 */
interface Handoff {
  url: string
  title: string
}

const HANDOFF_PREFIX = 'pam-session:'

/**
 * Read and remove (single-use) the handoff written by the opener. Returns null
 * if the key is missing, already consumed, or the stored value is unparseable.
 */
export function consumeHandoff(key: string): Handoff | null {
  if (!key) return null
  const storageKey = HANDOFF_PREFIX + key
  let raw: string | null = null
  try {
    raw = window.localStorage.getItem(storageKey)
    // Remove immediately so a reload / second window can't replay the token.
    window.localStorage.removeItem(storageKey)
  } catch {
    return null
  }
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw) as Partial<Handoff>
    if (typeof parsed?.url === 'string' && parsed.url) {
      return { url: parsed.url, title: typeof parsed.title === 'string' ? parsed.title : 'Session' }
    }
  } catch {
    // fall through to null
  }
  return null
}

export function PamSessionWindow() {
  const [params] = useSearchParams()
  const key = params.get('k') ?? ''

  // Consume the single-use handoff exactly once on mount. Doing it lazily in
  // useState guarantees the localStorage entry is removed before any re-render
  // (StrictMode double-invokes effects, which would otherwise "consume" twice).
  const [handoff] = useState<Handoff | null>(() => consumeHandoff(key))

  const iframeRef = useRef<HTMLIFrameElement | null>(null)
  const [reloadKey, setReloadKey] = useState(0)
  const phase = useGuacSessionPhase(iframeRef, !!handoff, reloadKey)

  useEffect(() => {
    if (handoff) document.title = handoff.title
  }, [handoff])

  // No / expired handoff → OpenIDX "expired" card, never a guac frame.
  if (!handoff) {
    return (
      <SessionCard
        heading="This session link has expired"
        body="Launch it again from the Connections console to start a new session."
      />
    )
  }

  const showOverlay = phase === 'ended' || phase === 'failed'

  return (
    <div className="fixed inset-0 flex flex-col bg-black">
      <div className="flex items-center justify-between px-3 py-2 border-b bg-muted/40 shrink-0">
        <div className="flex items-center gap-2 text-sm min-w-0">
          <span className="font-medium truncate">{handoff.title}</span>
          <span
            className={
              phase === 'active'
                ? 'text-green-600'
                : showOverlay
                  ? 'text-red-600'
                  : 'text-muted-foreground'
            }
          >
            ● {phase === 'active' ? 'connected' : phase === 'loading' ? 'connecting' : phase}
          </span>
        </div>
        <button
          className="text-sm px-3 py-1 rounded-md border hover:bg-muted"
          onClick={() => window.close()}
        >
          Disconnect
        </button>
      </div>

      <div className="relative flex-1 min-h-0 bg-black">
        {/* Only mount the guac frame while the session is (or may become) live.
            Once it's ended/failed we unmount it so the user can never glimpse
            Guacamole's home/manager chrome. */}
        {!showOverlay && (
          <iframe
            key={reloadKey}
            ref={iframeRef}
            src={handoff.url}
            title={handoff.title}
            className="w-full h-full border-0"
          />
        )}

        {showOverlay && (
          <SessionCard
            heading={phase === 'ended' ? 'Session ended' : `Couldn't connect to ${handoff.title}`}
            body={
              phase === 'ended'
                ? 'The remote session was closed. Launch it again from the console to start a new session.'
                : 'The remote session could not be established. This may be temporary, or you may not have access to the target.'
            }
            actions={
              <>
                <Button variant="outline" onClick={() => window.close()}>Close window</Button>
                <Button onClick={() => setReloadKey((k) => k + 1)}>Try again</Button>
              </>
            }
          />
        )}
      </div>
    </div>
  )
}

/** OpenIDX-branded full-window card — never Guacamole's own chrome. */
function SessionCard({
  heading,
  body,
  actions,
}: {
  heading: string
  body: string
  actions?: React.ReactNode
}) {
  return (
    <div className="fixed inset-0 flex items-center justify-center bg-background p-6">
      <div className="max-w-md w-full rounded-lg border bg-card p-6 text-center shadow-sm">
        <div className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-red-100">
          <AlertTriangle className="h-5 w-5 text-red-600" />
        </div>
        <h2 className="text-lg font-semibold">{heading}</h2>
        <p className="mt-1 text-sm text-muted-foreground">{body}</p>
        <div className="mt-4 flex justify-center gap-2">
          {actions ?? <Button onClick={() => window.close()}>Close window</Button>}
        </div>
      </div>
    </div>
  )
}
