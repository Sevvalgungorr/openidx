import { useEffect, useRef, useState, type RefObject } from 'react'
import { AlertTriangle } from 'lucide-react'
import { Dialog, DialogContent } from '../ui/dialog'
import { Button } from '../ui/button'

/**
 * In-app host for a same-origin Apache Guacamole session.
 *
 * PAM launches used to `window.open(connect_url, '_blank')`, which drops the
 * end user straight into Guacamole's own SPA. When a session FAILS, Guacamole
 * navigates to its home/connection-manager screen — exposing the connection
 * list, the shared account, and internal `pam-<uuid>` names. We must NEVER
 * show Guacamole's own chrome.
 *
 * Instead we frame the (same-origin) Guacamole client URL inside an OpenIDX
 * dialog and watch the iframe's hash route. Guacamole client sessions live at
 * `#/client/<id>`; anything else (`#/`, `#/home`, `#/settings`, the manager)
 * means the session died or never started. As soon as the frame leaves — or
 * never reaches — a client route, we tear the iframe down and paint our own
 * overlay so the user only ever sees OpenIDX messaging.
 */
interface Props {
  url: string
  title: string
  open: boolean
  onClose: () => void
}

/**
 * Pure classifier for a Guacamole location hash. Exported for unit testing so
 * the monitoring decision doesn't depend on real iframe navigation.
 *
 * A Guacamole client session lives at `#/client/<connection-id>...`. Every
 * other route (home, settings, connection manager, empty) is "other" and means
 * we should stop showing the frame.
 */
export function classifyGuacHash(hash: string): 'client' | 'other' {
  return hash.includes('/client/') ? 'client' : 'other'
}

// How long we wait for the frame to reach a client route before assuming the
// connection failed, and how often we poll the frame's hash.
const CONNECT_GRACE_MS = 20_000
const POLL_INTERVAL_MS = 1000

export type Phase = 'loading' | 'active' | 'ended' | 'failed'

/**
 * Watch a framed same-origin Guacamole client and report its lifecycle phase.
 *
 * Polls the iframe's location hash: a `#/client/<id>` route means the session
 * is live ('active'); leaving that route after having reached it means the
 * session 'ended'; never reaching it inside the grace window means it 'failed'.
 * Callers unmount the iframe once the phase is terminal (ended/failed) so the
 * user can never glimpse Guacamole's own home/manager chrome.
 *
 * `active` re-runs the effect (via the deps) so both the in-app dialog and the
 * standalone session window share exactly one copy of this monitoring logic.
 *
 * @param iframeRef ref to the framed guac client
 * @param active    whether monitoring should run (frame is/should be mounted)
 * @param resetKey  bump to restart the grace window (e.g. a "Try again" retry)
 */
export function useGuacSessionPhase(
  iframeRef: RefObject<HTMLIFrameElement | null>,
  active: boolean,
  resetKey: number = 0,
): Phase {
  const [phase, setPhase] = useState<Phase>('loading')

  useEffect(() => {
    if (!active) return
    // Reset for each fresh open / retry.
    setPhase('loading')
    const mountedAt = Date.now()
    let reachedClient = false

    const tick = () => {
      // While we're showing our own overlay there's no iframe to inspect.
      let hash: string
      try {
        hash = iframeRef.current?.contentWindow?.location?.hash ?? ''
      } catch {
        // Cross-origin/in-flight navigation can momentarily throw; ignore and
        // let the grace-period logic below decide.
        hash = ''
      }

      const kind = classifyGuacHash(hash)
      if (kind === 'client') {
        reachedClient = true
        setPhase('active')
        return
      }

      // Non-client route.
      if (reachedClient) {
        // We were in a live session and it left the client route → it ended.
        setPhase('ended')
      } else if (Date.now() - mountedAt > CONNECT_GRACE_MS) {
        // Never reached a client route within the grace window → never connected.
        setPhase('failed')
      }
      // else: still within the grace window, keep waiting (phase stays 'loading').
    }

    const id = window.setInterval(tick, POLL_INTERVAL_MS)
    return () => window.clearInterval(id)
  }, [iframeRef, active, resetKey])

  return phase
}

export function GuacSessionViewer({ url, title, open, onClose }: Props) {
  const iframeRef = useRef<HTMLIFrameElement | null>(null)
  // Bumping this remounts the iframe for "Try again" (fresh src load) and
  // restarts the phase monitor's grace window.
  const [reloadKey, setReloadKey] = useState(0)
  const phase = useGuacSessionPhase(iframeRef, open, reloadKey)

  const showOverlay = phase === 'ended' || phase === 'failed'

  const retry = () => {
    setReloadKey((k) => k + 1)
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent
        className="max-w-[95vw] w-[95vw] h-[90vh] p-0 overflow-hidden gap-0 flex flex-col"
        // Guacamole grabs pointer/keyboard focus; radix's default
        // focus-trap/close-on-outside-interact would fight it. Keep our
        // explicit Disconnect button as the way out.
        onInteractOutside={(e) => e.preventDefault()}
      >
        <div className="flex items-center justify-between px-3 py-2 border-b bg-muted/40 shrink-0">
          <div className="flex items-center gap-2 text-sm min-w-0">
            <span className="font-medium truncate">{title}</span>
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
            onClick={onClose}
          >
            Disconnect
          </button>
        </div>

        <div className="relative flex-1 min-h-0 bg-black">
          {/* Only mount the guac frame while the session is (or may become)
              live. Once we've decided it ended/failed we unmount it so the
              user can never glimpse Guacamole's home/manager chrome. */}
          {!showOverlay && (
            <iframe
              key={reloadKey}
              ref={iframeRef}
              src={url}
              title={title}
              className="w-full h-full border-0"
            />
          )}

          {showOverlay && (
            <div className="absolute inset-0 flex items-center justify-center bg-background p-6">
              <div className="max-w-md w-full rounded-lg border bg-card p-6 text-center shadow-sm">
                <div className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-red-100">
                  <AlertTriangle className="h-5 w-5 text-red-600" />
                </div>
                <h2 className="text-lg font-semibold">
                  {phase === 'ended' ? 'Session ended' : `Couldn't connect to ${title}`}
                </h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  {phase === 'ended'
                    ? 'The remote session was closed. Reconnect to start a new session.'
                    : 'The remote session could not be established. This may be temporary, or you may not have access to the target.'}
                </p>
                <div className="mt-4 flex justify-center gap-2">
                  <Button variant="outline" onClick={onClose}>Close</Button>
                  <Button onClick={retry}>Try again</Button>
                </div>
              </div>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
