import { useEffect, useRef, useState } from 'react'
import { Button } from '../ui/button'
import { Maximize, Square, WifiOff, ExternalLink } from 'lucide-react'

/**
 * RelayRenderer is the admin-side view for a remote-support session whose
 * transport is "relay": the device streams VP8 frames as binary WebSocket
 * messages through the broker (no WebRTC/STUN — full-Ziti capable). We decode
 * them with WebCodecs VideoDecoder(VP8) onto a canvas, and send input as text
 * JSON on the same socket. Requires a Chromium-based browser (WebCodecs VP8);
 * the WebRTC path remains the cross-browser fallback.
 */
interface Props {
  wsUrl: string
  mode: 'interactive' | 'view'
  onEnd: () => void
  // onPopOut, when provided, shows a "Pop out" button that opens the session in
  // a dedicated window (only meaningful in the embedded/dialog context).
  onPopOut?: () => void
  // autoFullscreen requests fullscreen automatically once streaming starts.
  // Used by the standalone pop-out window.
  autoFullscreen?: boolean
}

type RelayState = 'connecting' | 'streaming' | 'error' | 'closed'

// A 1-byte header precedes each VP8 frame: bit0 = keyframe.
const RELAY_FLAG_KEYFRAME = 0x01

export function RelayRenderer({ wsUrl, mode, onEnd, onPopOut, autoFullscreen }: Props) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const overlayRef = useRef<HTMLDivElement | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const decoderRef = useRef<VideoDecoder | null>(null)
  const controlActiveRef = useRef<boolean>(mode === 'interactive')
  const gotKeyRef = useRef(false)
  const [state, setState] = useState<RelayState>('connecting')
  const [errorMessage, setErrorMessage] = useState('')
  const [controlActive, setControlActive] = useState(mode === 'interactive')
  // reconnectNonce forces the connect effect to tear down and re-run. The relay
  // start-of-session has an inherent race: the admin WS may open before the
  // device has (a) granted consent [broker returns 403] or (b) connected its own
  // leg over the Ziti overlay [no frames yet]. Rather than dying on the first
  // close, auto-reconnect a bounded number of times with backoff so the viewer
  // reliably latches on once the device side is ready.
  const [reconnectNonce, setReconnectNonce] = useState(0)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  // Nonce at which we last had a healthy stream; the retry budget is measured
  // relative to it, so a drop after a good stream gets a fresh set of retries.
  const lastGoodNonceRef = useRef(0)

  useEffect(() => {
    if (typeof VideoDecoder === 'undefined') {
      setState('error')
      setErrorMessage('This browser lacks WebCodecs VP8 (use Chrome/Edge, or switch the session to WebRTC).')
      return
    }

    const ws = new WebSocket(wsUrl, tokenSubprotocols())
    ws.binaryType = 'arraybuffer'
    wsRef.current = ws

    // No-frames watchdog state (declared before the decoder so its output
    // callback can mark the first frame). Armed in ws.onopen below.
    let framesSeen = false
    const markFrameSeen = () => {
      framesSeen = true
    }

    // WebCodecs VP8 decoder -> canvas.
    const decoder = new VideoDecoder({
      output: (frame) => {
        const c = canvasRef.current
        if (c) {
          if (c.width !== frame.displayWidth || c.height !== frame.displayHeight) {
            c.width = frame.displayWidth
            c.height = frame.displayHeight
          }
          const ctx = c.getContext('2d')
          if (ctx) ctx.drawImage(frame, 0, 0)
          setState('streaming')
          markFrameSeen()
          // Healthy frame: rebase the retry budget to now so a later genuine
          // drop still gets a full set of reconnect attempts.
          lastGoodNonceRef.current = reconnectNonce
        }
        frame.close()
      },
      error: (e) => {
        // Decode errors usually mean we started mid-stream without a keyframe;
        // request one and keep going.
        console.warn('relay decode error', e)
        requestKeyframe()
      },
    })
    decoder.configure({ codec: 'vp8' })
    decoderRef.current = decoder

    ws.onopen = () => {
      if (controlActiveRef.current) sendJSON({ event: 'control_state', active: true })
      requestKeyframe()
    }

    // No-frames watchdog: if the socket stays open but no decoded frame ever
    // arrives, the viewer would sit on "Connecting…" forever. That happens when
    // the device connected but sends no video — typically a video-less agent
    // build (pure-Go/no-capture) or a capture that failed to start. After a
    // grace period with zero frames, surface a clear error instead of hanging.
    const noFrameWatchdog = setTimeout(() => {
      if (!framesSeen) {
        setErrorMessage(
          'No screen video received. The device connected but sent no frames — it may be running an agent build without screen capture, or capture failed to start. Check the agent logs on the device.',
        )
        setState((p) => (p === 'closed' ? p : 'error'))
      }
    }, 12000)
    // On an unexpected close/error, auto-reconnect with backoff until the device
    // side is ready. This absorbs the start-of-session race (403 while consent is
    // pending, or no frames yet while the device's overlay leg connects) so the
    // viewer latches on reliably instead of dying on the first close.
    const scheduleReconnect = () => {
      if (reconnectNonce - lastGoodNonceRef.current >= 8) {
        setState((p) => (p === 'closed' ? p : 'error'))
        return
      }
      setState((p) => (p === 'closed' ? p : 'connecting'))
      // Reset keyframe gating so a fresh connection waits for a new keyframe.
      gotKeyRef.current = false
      const attempts = reconnectNonce - lastGoodNonceRef.current
      const delay = Math.min(500 + attempts * 500, 3000)
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = setTimeout(() => setReconnectNonce((n) => n + 1), delay)
    }
    ws.onclose = () => scheduleReconnect()
    ws.onerror = () => scheduleReconnect()
    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') return // control text (unused inbound)
      const buf = new Uint8Array(ev.data as ArrayBuffer)
      if (buf.length < 2) return
      const isKey = (buf[0] & RELAY_FLAG_KEYFRAME) !== 0
      const payload = buf.subarray(1)
      // Wait for the first keyframe before feeding delta frames to the decoder.
      if (!gotKeyRef.current) {
        if (!isKey) return
        gotKeyRef.current = true
      }
      try {
        decoder.decode(
          new EncodedVideoChunk({
            type: isKey ? 'key' : 'delta',
            timestamp: performance.now() * 1000,
            data: payload,
          }),
        )
      } catch (err) {
        console.warn('relay decode threw', err)
      }
    }

    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
      clearTimeout(noFrameWatchdog)
      // Detach handlers before closing so a normal unmount/reconnect teardown
      // doesn't re-trigger scheduleReconnect via onclose.
      ws.onclose = null
      ws.onerror = null
      try { ws.close() } catch { /* already closed */ }
      try { decoder.close() } catch { /* already closed */ }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wsUrl, reconnectNonce])

  function sendJSON(obj: Record<string, unknown>) {
    const ws = wsRef.current
    if (ws && ws.readyState === WebSocket.OPEN) {
      try { ws.send(JSON.stringify(obj)) } catch { /* not open */ }
    }
  }

  function requestKeyframe() {
    gotKeyRef.current = false
    sendJSON({ event: 'request_keyframe' })
  }

  function sendInput(ev: Record<string, unknown>) {
    if (!controlActiveRef.current) return
    sendJSON(ev)
  }

  // Map a pointer event to the device's 0..1000 coordinate space, accounting for
  // the canvas's letterbox inside the overlay (object-contain).
  function coords(e: React.PointerEvent<HTMLDivElement>) {
    const rect = overlayRef.current?.getBoundingClientRect()
    const c = canvasRef.current
    if (!rect || !c || c.width === 0 || c.height === 0) return { x: 0, y: 0 }
    const videoAR = c.width / c.height
    const boxAR = rect.width / rect.height
    // Letterbox the video inside the overlay (object-contain): compute the
    // content rect (cw/ch) and its offset (cx/cy) so pointer coords map to the
    // visible frame, not the black bars.
    let cw: number, ch: number, cx: number, cy: number
    if (videoAR > boxAR) {
      cw = rect.width
      ch = rect.width / videoAR
      cx = rect.left
      cy = rect.top + (rect.height - ch) / 2
    } else {
      ch = rect.height
      cw = rect.height * videoAR
      cy = rect.top
      cx = rect.left + (rect.width - cw) / 2
    }
    const clamp = (v: number) => Math.max(0, Math.min(1, v))
    return { x: clamp((e.clientX - cx) / cw) * 1000, y: clamp((e.clientY - cy) / ch) * 1000 }
  }

  const downAt = useRef<{ x: number; y: number; t: number } | null>(null)
  function onPointerDown(e: React.PointerEvent<HTMLDivElement>) {
    if (mode !== 'interactive') return
    e.currentTarget.focus()
    downAt.current = { ...coords(e), t: Date.now() }
  }
  function onPointerUp(e: React.PointerEvent<HTMLDivElement>) {
    if (mode !== 'interactive' || !downAt.current) return
    const p = coords(e)
    const s = downAt.current
    const dist = Math.hypot(p.x - s.x, p.y - s.y)
    const dur = Date.now() - s.t
    if (dist < 20) sendInput({ event: 'tap', x: p.x, y: p.y, duration_ms: Math.max(50, dur) })
    else sendInput({ event: 'swipe', x: s.x, y: s.y, x2: p.x, y2: p.y, duration_ms: Math.max(100, dur) })
    downAt.current = null
  }
  function onKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    if (mode !== 'interactive') return
    if (e.key === 'Escape') { sendInput({ event: 'global_action', action: 'back' }); e.preventDefault() }
  }

  function toggleControl() {
    setControlActive((prev) => {
      const next = !prev
      controlActiveRef.current = next
      sendJSON({ event: 'control_state', active: next })
      return next
    })
  }

  function enterFullscreen() {
    overlayRef.current?.requestFullscreen?.().then(() => overlayRef.current?.focus()).catch(() => {})
  }

  // Auto-fullscreen once the stream is live (pop-out window only). Guarded so it
  // only fires on the first transition into streaming.
  const autoFsDone = useRef(false)
  useEffect(() => {
    if (autoFullscreen && state === 'streaming' && !autoFsDone.current) {
      autoFsDone.current = true
      enterFullscreen()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoFullscreen, state])

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {state === 'streaming' ? 'Live (relay / Ziti)' : state === 'connecting' ? 'Connecting…' : state === 'error' ? (errorMessage || 'Disconnected') : 'Closed'}
        </div>
        <div className="flex items-center gap-2">
          {mode === 'interactive' && (
            <>
              <Button variant={controlActive ? 'default' : 'outline'} size="sm" onClick={toggleControl}>
                {controlActive ? 'Release control' : 'Take control'}
              </Button>
              <Button variant="outline" size="sm" disabled={!controlActive} onClick={() => sendInput({ event: 'global_action', action: 'back' })}>Back</Button>
              <Button variant="outline" size="sm" disabled={!controlActive} onClick={() => sendInput({ event: 'global_action', action: 'home' })}>Home</Button>
            </>
          )}
          <Button variant="outline" size="sm" onClick={enterFullscreen}><Maximize className="mr-1 h-3 w-3" /> Fullscreen</Button>
          {onPopOut && (
            <Button variant="outline" size="sm" onClick={onPopOut} title="Open in a separate window (great for a second monitor)">
              <ExternalLink className="mr-1 h-3 w-3" /> Pop out
            </Button>
          )}
          <Button variant="destructive" size="sm" onClick={onEnd}><Square className="mr-1 h-3 w-3" /> End session</Button>
        </div>
      </div>
      <div
        ref={overlayRef}
        tabIndex={0}
        onPointerDown={onPointerDown}
        onPointerUp={onPointerUp}
        onKeyDown={onKeyDown}
        onClick={(e) => e.stopPropagation()}
        style={{ touchAction: 'none' }}
        className="relative bg-black rounded-md aspect-video overflow-hidden flex items-center justify-center focus:outline-none focus:ring-2 focus:ring-primary cursor-crosshair fullscreen:aspect-auto fullscreen:h-screen fullscreen:w-screen fullscreen:rounded-none"
      >
        <canvas ref={canvasRef} className="max-h-full max-w-full object-contain pointer-events-none" />
        {state !== 'streaming' && (
          <div className="absolute inset-0 flex items-center justify-center text-white/80 text-sm">
            {state === 'error' ? (
              <span className="flex items-center gap-2"><WifiOff className="h-4 w-4" /> {errorMessage || 'Disconnected'}</span>
            ) : state === 'connecting' ? 'Connecting…' : 'Closed'}
          </div>
        )}
      </div>
      <p className="text-xs text-muted-foreground">
        Relay transport (full Ziti): media + control flow through the broker, no P2P/STUN. Click = tap, drag = swipe, Esc = back.
      </p>
    </div>
  )
}

// tokenSubprotocols mirrors the WebRTC viewer: browsers can't set an Auth header
// on a WebSocket, so the OAuth bearer rides as a subprotocol.
function tokenSubprotocols(): string[] {
  const token = localStorage.getItem('token')
  return token ? [`bearer.${token}`] : []
}
