import { useEffect, useRef, useState } from 'react'
import { Button } from '../ui/button'
import { Badge } from '../ui/badge'
import { Circle, Maximize, Square, WifiOff } from 'lucide-react'
import { api } from '../../lib/api'

/**
 * Admin-side WebRTC peer for a remote-support session.
 *
 * Wiring:
 *   - Opens the admin WebSocket on mount; receives offer / ICE from the
 *     device side via the in-memory broker.
 *   - Builds an RTCPeerConnection, plays the inbound video track on a
 *     <video> element.
 *   - In interactive mode, creates a data channel ("openidx-input") and
 *     forwards pointer / keyboard events as InputEventMessage payloads.
 *
 * Token auth: the WebSocket URL is opened on the admin side, where the
 * APISIX layer already attaches the OAuth Bearer. The agent side
 * authenticates with its own headers (handled server-side).
 */

interface Props {
  wsUrl: string
  mode: 'interactive' | 'view'
  iceServers: RTCIceServer[]
  /** Session UUID — used to address /recording/chunk + /recording/finalize. */
  sessionId: string
  /** When true, MediaRecorder captures the inbound stream and chunks
   *  upload to the server every [recordingTimesliceMs] ms. */
  recordingEnabled: boolean
  /** Optional override; defaults to 5 s. */
  recordingTimesliceMs?: number
  onClose: () => void
  onEnd: () => void
}

type ConnState = 'connecting' | 'awaiting-offer' | 'negotiating' | 'streaming' | 'closed' | 'error'
type RecState = 'off' | 'arming' | 'recording' | 'finalizing' | 'failed'

export function RemoteSupportViewer({
  wsUrl,
  mode,
  iceServers,
  sessionId,
  recordingEnabled,
  recordingTimesliceMs = 5000,
  onClose: _onClose,
  onEnd,
}: Props) {
  const videoRef = useRef<HTMLVideoElement | null>(null)
  const liveStreamRef = useRef<MediaStream | null>(null)
  const overlayRef = useRef<HTMLDivElement | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const pcRef = useRef<RTCPeerConnection | null>(null)
  const inputChannelRef = useRef<RTCDataChannel | null>(null)
  const controlActiveRef = useRef<boolean>(mode === 'interactive')
  const recorderRef = useRef<MediaRecorder | null>(null)
  const chunkIndexRef = useRef<number>(0)
  const recordedStreamRef = useRef<MediaStream | null>(null)
  const [state, setState] = useState<ConnState>('connecting')
  const [errorMessage, setErrorMessage] = useState<string>('')
  const [recState, setRecState] = useState<RecState>('off')
  // Live control toggle: in an interactive session the admin can hand control
  // back and forth without restarting. When false, input is not forwarded and
  // the device is told to drop its "being controlled" indicator. Starts true
  // for interactive sessions (matches today's behavior), always false in view.
  const [controlActive, setControlActive] = useState<boolean>(mode === 'interactive')
  // reconnectNonce forces the connect effect to tear down and re-run. A
  // watchdog bumps it when the viewer connects but no video arrives (the device
  // peer wasn't ready yet, so our offer was missed) — automating the manual
  // "close and reopen the viewer" the operator had to do.
  const [reconnectNonce, setReconnectNonce] = useState(0)
  const gotVideoRef = useRef(false)

  useEffect(() => {
    const ws = openSignalingSocket(wsUrl)
    wsRef.current = ws

    const pc = new RTCPeerConnection({ iceServers })
    pcRef.current = pc

    pc.ontrack = (e) => {
      const stream = e.streams[0] ?? new MediaStream([e.track])
      gotVideoRef.current = true
      liveStreamRef.current = stream
      attachStream(stream)
      setState('streaming')
      recordedStreamRef.current = stream
      if (recordingEnabled && !recorderRef.current) {
        try { startMediaRecorder(stream) }
        catch (err) {
          console.warn('MediaRecorder start failed', err)
          setRecState('failed')
        }
      }
    }
    pc.onicecandidate = (e) => {
      if (e.candidate && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'ice',
          payload: {
            candidate: e.candidate.candidate,
            sdp_mid: e.candidate.sdpMid,
            sdp_m_line_index: e.candidate.sdpMLineIndex,
          },
        }))
      }
    }
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'failed' || pc.connectionState === 'disconnected') {
        setState('error')
        setErrorMessage(`peer connection ${pc.connectionState}`)
      }
    }
    // NOTE: we deliberately do NOT createDataChannel here. The browser is the
    // ANSWERER (the device sends the offer), and an SDP answer cannot introduce
    // a data-channel m-line the offer omitted — a channel created on this side
    // would never be negotiated, so input silently failed. The device now
    // creates the "openidx-input" channel before its offer; we receive it via
    // ondatachannel below and send input + control_state on it.
    pc.ondatachannel = (e) => {
      if (e.channel.label === 'openidx-input') {
        inputChannelRef.current = e.channel
        const dc = e.channel
        // The device gates ALL input on control_state and starts OFF, so we
        // announce our (default-on for interactive) control state the moment
        // the channel opens; otherwise the device drops every tap/key.
        const announce = () => {
          if (controlActiveRef.current) {
            try { dc.send(JSON.stringify({ event: 'control_state', active: true })) } catch { /* not open */ }
          }
        }
        if (dc.readyState === 'open') announce()
        else dc.onopen = announce
      }
    }

    ws.onopen = () => setState('awaiting-offer')
    ws.onclose = () => {
      // Signaling is only needed to negotiate + trickle ICE. Once the peer
      // connection is established, video + input flow directly peer-to-peer
      // over WebRTC, so a signaling WS close (e.g. proxy idle timeout) must NOT
      // tear down a live session. pcRef is always current (unlike the captured
      // `state`), so gate the error on whether we reached a usable peer.
      const pcState = pcRef.current?.connectionState
      const live = pcState === 'connected' || pcState === 'connecting'
      if (!live) {
        setState((prev) => (prev === 'closed' || prev === 'streaming' ? prev : 'error'))
        setErrorMessage((prev) => (prev ? prev : 'signaling channel closed'))
      }
    }
    ws.onerror = () => {
      // Same rationale as onclose: a signaling-transport error must not tear
      // down a session whose media path is already (or nearly) up.
      const pcState = pcRef.current?.connectionState
      const live = pcState === 'connected' || pcState === 'connecting'
      if (!live) {
        setState((prev) => (prev === 'closed' || prev === 'streaming' ? prev : 'error'))
        setErrorMessage((prev) => (prev ? prev : 'signaling error'))
      }
    }
    ws.onmessage = async (ev) => {
      const envelope = parseEnvelope(ev.data)
      if (!envelope) return
      if (envelope.type === 'sdp') {
        const { sdp, type } = envelope.payload as { sdp: string; type: string }
        setState('negotiating')
        if (type === 'offer') {
          await pc.setRemoteDescription({ type: 'offer', sdp })
          const answer = await pc.createAnswer()
          await pc.setLocalDescription(answer)
          ws.send(JSON.stringify({
            type: 'sdp',
            payload: { sdp: answer.sdp ?? '', type: 'answer' },
          }))
        } else if (type === 'answer') {
          await pc.setRemoteDescription({ type: 'answer', sdp })
        }
      } else if (envelope.type === 'ice') {
        const ice = envelope.payload as { candidate: string; sdp_mid?: string; sdp_m_line_index?: number }
        try {
          await pc.addIceCandidate({
            candidate: ice.candidate,
            sdpMid: ice.sdp_mid,
            sdpMLineIndex: ice.sdp_m_line_index,
          })
        } catch (err) {
          console.warn('addIceCandidate failed', err)
        }
      }
    }

    // Watchdog: if we don't receive a video track within a few seconds, the
    // device peer probably wasn't connected when we sent our answer (so our
    // signaling was missed). Rather than sit on a black screen until the
    // operator manually closes + reopens, bump reconnectNonce to tear this
    // connection down and try again. Retries a handful of times, then surfaces
    // a clear error instead of sitting on "Connecting…" forever — the usual
    // cause after retries are exhausted is a device running a video-less agent
    // build (the pure-Go/no-capture variant negotiates the session but sends no
    // frames), which otherwise looks like an infinite connect.
    gotVideoRef.current = false
    const watchdog = setTimeout(() => {
      if (gotVideoRef.current) return
      if (reconnectNonce < 6) {
        setReconnectNonce((n) => n + 1)
      } else {
        setState('error')
        setErrorMessage(
          'No screen video received. The device connected but sent no frames — it may be running an agent build without screen capture, or screen capture failed to start. Check the agent logs on the device.',
        )
      }
    }, 4000)

    return () => {
      // Best-effort teardown — each may already be closed; ignore throws.
      clearTimeout(watchdog)
      try { stopRecording() } catch { /* already stopped */ }
      try { ws.close() } catch { /* already closed */ }
      try { pc.close() } catch { /* already closed */ }
      setState('closed')
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wsUrl, reconnectNonce])

  // attachStream binds a MediaStream to the <video> and forces playback. The
  // ontrack event can fire before the browser has a keyframe to paint, or while
  // the element is still behind the "connecting" overlay, leaving a black frame
  // until the viewer is reopened. Re-attaching + play() (and retrying a few
  // times) makes the first frame render as soon as it arrives, without needing
  // a manual close/reopen.
  function attachStream(stream: MediaStream) {
    const v = videoRef.current
    if (!v) return
    if (v.srcObject !== stream) v.srcObject = stream
    const tryPlay = (n: number) => {
      v.play?.().catch(() => {
        if (n > 0) setTimeout(() => tryPlay(n - 1), 200)
      })
    }
    tryPlay(5)
  }

  // enterFullscreen makes the video overlay fill the screen — the most reliable
  // way to control at 1:1 pixel accuracy (the letterbox math is exact and the
  // pointer has the whole display to aim in). Esc exits (browser default). We
  // focus the overlay so keyboard input keeps flowing in fullscreen.
  function enterFullscreen() {
    const el = overlayRef.current
    if (!el) return
    const req = el.requestFullscreen?.bind(el)
    if (req) {
      req().then(() => el.focus()).catch(() => { /* user gesture / policy */ })
    }
  }

  // Whenever we enter the streaming state (or the element remounts), make sure
  // the live stream is actually attached and playing. This catches the race
  // where ontrack fired before the <video> ref existed or before the overlay
  // revealed it.
  useEffect(() => {
    if (state === 'streaming' && liveStreamRef.current) {
      attachStream(liveStreamRef.current)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state])

  function sendInput(event: Record<string, unknown>) {
    if (!controlActiveRef.current) return
    const ch = inputChannelRef.current
    if (!ch || ch.readyState !== 'open') return
    ch.send(JSON.stringify(event))
  }

  // sendControlState notifies the device whether the admin currently holds
  // control, so it can show/hide its "being controlled" banner. Sent over the
  // same input channel as a distinct event the agent recognizes.
  function sendControlState(active: boolean) {
    const ch = inputChannelRef.current
    if (ch && ch.readyState === 'open') {
      ch.send(JSON.stringify({ event: 'control_state', active }))
    }
  }

  function toggleControl() {
    setControlActive((prev) => {
      const next = !prev
      controlActiveRef.current = next
      sendControlState(next)
      return next
    })
  }

  /**
   * Pick a MediaRecorder codec the browser actually supports. Chromium
   * picks `video/webm;codecs=vp8,opus` by default but Safari only
   * understands `video/mp4` flavors. We probe in order and bail out if
   * nothing matches.
   */
  function preferredRecorderMime(): string | null {
    if (typeof MediaRecorder === 'undefined') return null
    const candidates = [
      'video/webm;codecs=vp8',
      'video/webm;codecs=vp9',
      'video/webm',
      'video/mp4',
    ]
    return candidates.find((m) => MediaRecorder.isTypeSupported(m)) ?? null
  }

  function startMediaRecorder(stream: MediaStream) {
    const mime = preferredRecorderMime()
    if (!mime) {
      setRecState('failed')
      return
    }
    setRecState('arming')
    chunkIndexRef.current = 0
    const recorder = new MediaRecorder(stream, { mimeType: mime })
    recorderRef.current = recorder

    recorder.ondataavailable = async (ev) => {
      if (!ev.data || ev.data.size === 0) return
      const index = chunkIndexRef.current++
      try {
        await uploadChunk(ev.data, index)
      } catch (err) {
        console.warn('recording chunk upload failed', { index, err })
      }
    }
    recorder.onstart = () => setRecState('recording')
    recorder.onerror = (ev: Event) => {
      console.warn('MediaRecorder error', ev)
      setRecState('failed')
    }
    recorder.onstop = async () => {
      setRecState('finalizing')
      try {
        await api.post(`/api/v1/access/remote-support/sessions/${sessionId}/recording/finalize`)
        setRecState('off')
      } catch (err) {
        console.warn('finalize failed', err)
        setRecState('failed')
      }
    }
    recorder.start(recordingTimesliceMs)
  }

  async function uploadChunk(blob: Blob, index: number) {
    // axios doesn't handle raw octet-stream uploads as well as fetch does
    // here, so use fetch directly with the same Bearer header the api
    // client attaches. baseURL = window.location.origin in dev / prod.
    const token = localStorage.getItem('token')
    const url = `/api/v1/access/remote-support/sessions/${sessionId}/recording/chunk`
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Chunk-Index': String(index),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: blob,
    })
    if (!resp.ok) throw new Error(`chunk upload ${resp.status}`)
  }

  function stopRecording() {
    const rec = recorderRef.current
    if (rec && rec.state !== 'inactive') {
      rec.stop() // triggers final ondataavailable + onstop → finalize
    }
  }

  /**
   * Translate a pointer event on the overlay to normalized device-screen
   * coordinates in the 0..1000 range the device expects.
   *
   * The <video> is rendered with object-contain, so the actual picture is
   * letterboxed inside the overlay: it fills one axis and leaves black bars on
   * the other. Mapping the click against the raw overlay rect therefore lands
   * in the wrong spot (offset by the bar size and scaled wrong). We reconstruct
   * the real content rectangle from the video's intrinsic aspect ratio and map
   * the pointer relative to THAT, clamping to the picture so clicks on the bars
   * don't send out-of-range coordinates.
   */
  function pointerCoords(e: React.PointerEvent<HTMLDivElement>) {
    const rect = overlayRef.current?.getBoundingClientRect()
    if (!rect) return { x: 0, y: 0 }
    const vid = videoRef.current
    const vw = vid?.videoWidth || 0
    const vh = vid?.videoHeight || 0

    // Content rect defaults to the full overlay (before metadata / for square).
    let cx = rect.left
    let cy = rect.top
    let cw = rect.width
    let ch = rect.height
    if (vw > 0 && vh > 0 && rect.width > 0 && rect.height > 0) {
      const videoAR = vw / vh
      const boxAR = rect.width / rect.height
      if (videoAR > boxAR) {
        // Video is wider than the box: full width, letterbox top/bottom.
        cw = rect.width
        ch = rect.width / videoAR
        cx = rect.left
        cy = rect.top + (rect.height - ch) / 2
      } else {
        // Video is taller: full height, pillarbox left/right.
        ch = rect.height
        cw = rect.height * videoAR
        cy = rect.top
        cx = rect.left + (rect.width - cw) / 2
      }
    }
    const fx = (e.clientX - cx) / cw
    const fy = (e.clientY - cy) / ch
    const clamp = (v: number) => Math.max(0, Math.min(1, v))
    return { x: clamp(fx) * 1000, y: clamp(fy) * 1000 }
  }

  const pointerDownAt = useRef<{ x: number; y: number; t: number } | null>(null)

  function onPointerDown(e: React.PointerEvent<HTMLDivElement>) {
    if (mode !== 'interactive') return
    const { x, y } = pointerCoords(e)
    pointerDownAt.current = { x, y, t: Date.now() }
  }
  function onPointerUp(e: React.PointerEvent<HTMLDivElement>) {
    if (mode !== 'interactive' || !pointerDownAt.current) return
    const { x, y } = pointerCoords(e)
    const start = pointerDownAt.current
    const dx = x - start.x
    const dy = y - start.y
    const dist = Math.hypot(dx, dy)
    const duration = Date.now() - start.t
    if (dist < 20) {
      sendInput({ event: 'tap', x, y, duration_ms: Math.max(50, duration) })
    } else {
      sendInput({
        event: 'swipe',
        x: start.x, y: start.y, x2: x, y2: y,
        duration_ms: Math.max(100, duration),
      })
    }
    pointerDownAt.current = null
  }
  function onKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    if (mode !== 'interactive') return
    // Esc maps to the device Back action (most natural for the viewer).
    if (e.key === 'Escape') {
      sendInput({ event: 'global_action', action: 'back' })
      e.preventDefault()
      return
    }
    // Named keys carry both key_name (Accessibility fallback) and
    // key_code (IME path) so the device uses whichever is available.
    const named = NAMED_KEYS[e.key]
    if (named) {
      sendInput({ event: 'key', key_name: named.name, key_code: named.code })
      e.preventDefault()
      return
    }
    // Special navigation / editing keys that have no Accessibility
    // emulation — sent with an Android key_code, only effective when the
    // OpenIDX keyboard is the active input method on the device.
    const code = ANDROID_KEYCODES[e.key]
    if (code !== undefined) {
      sendInput({ event: 'key', key_code: code })
      e.preventDefault()
      return
    }
    // Printable characters go through the dedicated text input below so
    // we don't single-character-spam the data channel on every keystroke.
  }

  // Text-input state — kept separate from the overlay so the admin can
  // compose a longer string and commit it as one message instead of one
  // keystroke per data-channel frame.
  const [pendingText, setPendingText] = useState('')
  // Clipboard-push state. Distinct from pendingText: the device's
  // ClipboardManager.setPrimaryClip path is "paste this somewhere
  // later", not "type this into the focused field now".
  const [pendingClipboard, setPendingClipboard] = useState('')

  function sendPendingText() {
    if (!pendingText) return
    sendInput({ event: 'text', text: pendingText })
    setPendingText('')
  }

  function sendPendingClipboard() {
    if (!pendingClipboard) return
    sendInput({ event: 'clipboard', text: pendingClipboard })
    setPendingClipboard('')
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ConnectionStatus state={state} message={errorMessage} />
          {recordingEnabled && <RecordingIndicator state={recState} />}
        </div>
        <div className="flex items-center gap-2">
          {mode === 'interactive' && (
            <>
              <Button
                variant={controlActive ? 'default' : 'outline'}
                size="sm"
                onClick={toggleControl}
                title={controlActive ? 'You are controlling the device — click to release' : 'View-only — click to take control'}
              >
                {controlActive ? 'Release control' : 'Take control'}
              </Button>
              <Button variant="outline" size="sm" disabled={!controlActive} onClick={() => sendInput({ event: 'global_action', action: 'back' })}>
                Back
              </Button>
              <Button variant="outline" size="sm" disabled={!controlActive} onClick={() => sendInput({ event: 'global_action', action: 'home' })}>
                Home
              </Button>
              <Button variant="outline" size="sm" disabled={!controlActive} onClick={() => sendInput({ event: 'global_action', action: 'recents' })}>
                Recents
              </Button>
            </>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={enterFullscreen}
            title="Fullscreen (Esc to exit) — best for pixel-accurate control"
          >
            <Maximize className="mr-1 h-3 w-3" /> Fullscreen
          </Button>
          <Button variant="destructive" size="sm" onClick={onEnd}>
            <Square className="mr-1 h-3 w-3" /> End session
          </Button>
        </div>
      </div>

      <div
        ref={overlayRef}
        tabIndex={0}
        onPointerDown={(e) => { e.currentTarget.focus(); onPointerDown(e) }}
        onPointerUp={onPointerUp}
        onKeyDown={onKeyDown}
        // The video is the interactive control surface. Stop pointer events from
        // bubbling to the surrounding Radix Dialog (which otherwise treats a
        // click as an outside-interaction / focus change and blurs or dismisses
        // the surface). style touch-none prevents the browser from hijacking
        // drags as scroll/gestures.
        onClick={(e) => e.stopPropagation()}
        style={{ touchAction: 'none' }}
        className="relative bg-black rounded-md aspect-video overflow-hidden focus:outline-none focus:ring-2 focus:ring-primary cursor-crosshair fullscreen:aspect-auto fullscreen:h-screen fullscreen:w-screen fullscreen:rounded-none"
      >
        <video
          ref={videoRef}
          autoPlay
          playsInline
          muted
          // pointer-events-none so clicks land on the capturing overlay div, not
          // the <video> element (which would swallow them).
          className="absolute inset-0 h-full w-full object-contain pointer-events-none"
        />
        {state !== 'streaming' && (
          <div className="absolute inset-0 flex items-center justify-center text-white/80 text-sm">
            <Placeholder state={state} message={errorMessage} />
          </div>
        )}
      </div>

      <p className="text-xs text-muted-foreground">
        {mode === 'interactive'
          ? 'Tap = single press · drag = swipe · Esc = back · Enter / Backspace / Tab pass through · arrows + page keys need the OpenIDX keyboard active on the device.'
          : 'View-only — input is disabled for this session.'}
      </p>

      {mode === 'interactive' && (
        <div className="space-y-2 pt-1">
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={pendingText}
              onChange={(e) => setPendingText(e.target.value)}
              onKeyDown={(e) => {
                // Send on Enter; consume so the overlay's onKeyDown doesn't
                // also fire an 'enter' key event for the same press.
                if (e.key === 'Enter') {
                  e.preventDefault()
                  sendPendingText()
                }
              }}
              placeholder="Type and press Enter to inject into the focused field…"
              className="flex-1 h-9 rounded-md border border-input bg-background px-3 text-sm"
              disabled={state !== 'streaming'}
            />
            <Button
              variant="outline"
              size="sm"
              onClick={sendPendingText}
              disabled={!pendingText || state !== 'streaming'}
            >
              Send text
            </Button>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="text"
              value={pendingClipboard}
              onChange={(e) => setPendingClipboard(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault()
                  sendPendingClipboard()
                }
              }}
              placeholder="Push to device clipboard (user pastes wherever they need it)…"
              className="flex-1 h-9 rounded-md border border-input bg-background px-3 text-sm"
              disabled={state !== 'streaming'}
            />
            <Button
              variant="outline"
              size="sm"
              onClick={sendPendingClipboard}
              disabled={!pendingClipboard || state !== 'streaming'}
            >
              Push clipboard
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

function RecordingIndicator({ state }: { state: RecState }) {
  if (state === 'off') return null
  const label = state === 'recording' ? 'recording'
    : state === 'finalizing' ? 'finalizing recording…'
    : state === 'arming' ? 'recording (arming)'
    : state === 'failed' ? 'recording failed'
    : state
  const variant = state === 'recording' ? 'destructive'
    : state === 'failed' ? 'destructive'
    : 'secondary'
  return (
    <Badge variant={variant as any} className="gap-1">
      <Circle className="h-3 w-3 fill-current" /> {label}
    </Badge>
  )
}

function ConnectionStatus({ state, message }: { state: ConnState; message: string }) {
  const variant = state === 'streaming' ? 'success'
    : state === 'error' ? 'destructive'
    : 'secondary'
  const label = state === 'streaming' ? 'streaming'
    : state === 'connecting' ? 'connecting'
    : state === 'awaiting-offer' ? 'waiting for device'
    : state === 'negotiating' ? 'negotiating'
    : state === 'closed' ? 'closed'
    : `error${message ? `: ${message}` : ''}`
  return <Badge variant={variant as any}>{label}</Badge>
}

function Placeholder({ state, message }: { state: ConnState; message: string }) {
  if (state === 'error') {
    return (
      <div className="flex items-center gap-2">
        <WifiOff className="h-4 w-4" />
        <span>{message || 'connection failed'}</span>
      </div>
    )
  }
  return <span>{stateLabel(state)}</span>
}

function stateLabel(state: ConnState) {
  switch (state) {
    case 'connecting': return 'Connecting to signaling…'
    case 'awaiting-offer': return 'Waiting for the device to accept the consent prompt…'
    case 'negotiating': return 'Negotiating WebRTC peer…'
    case 'closed': return 'Session closed'
    default: return state
  }
}

function parseEnvelope(raw: unknown): { type: string; payload?: unknown } | null {
  if (typeof raw !== 'string') return null
  try {
    const obj = JSON.parse(raw)
    if (obj && typeof obj === 'object' && typeof obj.type === 'string') return obj
  } catch { /* ignore */ }
  return null
}

// NAMED_KEYS carry both a name (Accessibility emulation path) and the
// Android KeyEvent code (IME path). The device picks whichever path is
// available — the IME when the OpenIDX keyboard is active, else the
// Accessibility ACTION_IME_ENTER / SET_TEXT emulation.
const NAMED_KEYS: Record<string, { name: string; code: number }> = {
  Enter: { name: 'enter', code: 66 },      // KEYCODE_ENTER
  Backspace: { name: 'backspace', code: 67 }, // KEYCODE_DEL
  Tab: { name: 'tab', code: 61 },          // KEYCODE_TAB
}

// ANDROID_KEYCODES maps browser KeyboardEvent.key values to Android
// KeyEvent.KEYCODE_* ints for keys that have no Accessibility emulation.
// These only land when the OpenIDX IME is the active input method on
// the device.
const ANDROID_KEYCODES: Record<string, number> = {
  ArrowUp: 19,     // KEYCODE_DPAD_UP
  ArrowDown: 20,   // KEYCODE_DPAD_DOWN
  ArrowLeft: 21,   // KEYCODE_DPAD_LEFT
  ArrowRight: 22,  // KEYCODE_DPAD_RIGHT
  Delete: 112,     // KEYCODE_FORWARD_DEL
  PageUp: 92,      // KEYCODE_PAGE_UP
  PageDown: 93,    // KEYCODE_PAGE_DOWN
  Home: 122,       // KEYCODE_MOVE_HOME
  End: 123,        // KEYCODE_MOVE_END
}

function openSignalingSocket(url: string): WebSocket {
  // Attach the OAuth bearer via subprotocol so the browser supplies it on
  // upgrade. The server broker doesn't read it, but APISIX upstream might.
  const token = localStorage.getItem('token')
  try {
    return token ? new WebSocket(url, [`bearer.${token}`]) : new WebSocket(url)
  } catch {
    return new WebSocket(url)
  }
}
