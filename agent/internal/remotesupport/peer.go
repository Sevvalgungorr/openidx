// Package remotesupport implements the DEVICE side of an OpenIDX remote-support
// session: it captures the screen, negotiates a WebRTC peer connection with the
// admin's browser (via the server's signaling broker), streams the screen as a
// VP8 video track, and applies inbound input events (pointer/keyboard) plus the
// admin's control_state signal.
//
// Layering (so the agent stays cross-compilable as pure Go):
//   - peer.go       — signaling + WebRTC peer + track pump. Pure Go (pion).
//   - source.go     — the VideoSource interface + a synthetic test source.
//   - capture_*.go  — real screen capture + VP8 encode, behind the `screenshare`
//     build tag (CGO/libvpx). A no-op stub otherwise.
//
// The admin viewer (web/admin-console/.../remote-support-viewer.tsx) is the
// OFFER-receiver, so the DEVICE creates the offer. Signaling envelopes on the
// WebSocket match the broker relay exactly:
//   - {"type":"sdp","payload":{"sdp":"...","type":"offer|answer"}}
//   - {"type":"ice","payload":{"candidate":"...","sdp_mid":"...","sdp_m_line_index":N}}
package remotesupport

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"go.uber.org/zap"
)

// SignalConn is the transport the peer uses to exchange signaling with the
// admin (the server's agent WebSocket). Kept small so tests can supply a pipe.
type SignalConn interface {
	// ReadJSON reads one signaling envelope.
	ReadJSON(v interface{}) error
	// WriteJSON writes one signaling envelope.
	WriteJSON(v interface{}) error
	// Close terminates the connection.
	Close() error
}

// envelope is a signaling message on the wire (matches the broker + viewer).
type envelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type sdpPayload struct {
	SDP  string `json:"sdp"`
	Type string `json:"type"`
}

type icePayload struct {
	Candidate     string `json:"candidate"`
	SDPMid        string `json:"sdp_mid"`
	SDPMLineIndex uint16 `json:"sdp_m_line_index"`
}

// InputEvent is an inbound control message from the admin (pointer/keyboard/
// global action). Applied by an InputSink when the admin holds control. The
// admin viewer sends normalized coordinates in the 0..1000 range (x/y), so a
// desktop sink scales them to the real screen size.
type InputEvent struct {
	Event      string  `json:"event"` // tap|swipe|text|key|clipboard|global_action|control_state
	Action     string  `json:"action,omitempty"`
	X          float64 `json:"x,omitempty"`
	Y          float64 `json:"y,omitempty"`
	X2         float64 `json:"x2,omitempty"` // swipe end x
	Y2         float64 `json:"y2,omitempty"` // swipe end y
	DurationMS int     `json:"duration_ms,omitempty"`
	Text       string  `json:"text,omitempty"`
	KeyName    string  `json:"key_name,omitempty"`
	KeyCode    int     `json:"key_code,omitempty"`
	Active     *bool   `json:"active,omitempty"` // for event=="control_state"
}

// InputSink applies inbound input to the device. A headless build uses a no-op.
type InputSink interface {
	Apply(ev InputEvent)
	// SetControlActive is called when the admin takes/releases control.
	SetControlActive(active bool)
}

// noopSink drops all input (used when no OS input injector is wired).
type noopSink struct{}

func (noopSink) Apply(InputEvent)      {}
func (noopSink) SetControlActive(bool) {}

// PeerConfig configures a device peer.
type PeerConfig struct {
	ICEServers []webrtc.ICEServer
	Source     VideoSource // required
	Input      InputSink   // optional; defaults to no-op
	Logger     *zap.Logger
}

// Peer is one device-side remote-support session.
type Peer struct {
	cfg    PeerConfig
	pc     *webrtc.PeerConnection
	track  *webrtc.TrackLocalStaticSample
	logger *zap.Logger

	mu     sync.Mutex
	closed bool
}

// Run negotiates the session over conn and streams until conn closes, the peer
// connection fails, or Close is called. Blocking; run it in its own goroutine.
func (p *Peer) Run(conn SignalConn) error {
	if p.cfg.Source == nil {
		return fmt.Errorf("remotesupport: a VideoSource is required")
	}
	if p.logger == nil {
		p.logger = zap.NewNop()
	}
	// Loud, actionable warning when this build cannot capture video: the session
	// will negotiate and honor input but the operator's viewer will show no
	// screen. This is the single most common "remote support connects but the
	// screen never appears" cause (a pure-Go/no-capture agent build).
	if !SourceHasVideo(p.cfg.Source) {
		p.logger.Warn("remote-support: this agent build has NO screen capture (video-less build); " +
			"the session will connect and accept input but send no video. Install the " +
			"screenshare-enabled agent build to stream the screen.")
	}
	sink := p.cfg.Input
	if sink == nil {
		sink = noopSink{}
	}

	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{ICEServers: p.cfg.ICEServers})
	if err != nil {
		return fmt.Errorf("new peer connection: %w", err)
	}
	p.pc = pc
	defer pc.Close()

	// One VP8 video track carrying the screen.
	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8}, "screen", "openidx-screen")
	if err != nil {
		return fmt.Errorf("new video track: %w", err)
	}
	sender, err := pc.AddTrack(track)
	if err != nil {
		return fmt.Errorf("add track: %w", err)
	}
	p.track = track

	// Read RTCP from the sender and force a keyframe whenever the browser sends
	// a PLI (Picture Loss Indication) or Full Intra Request. A viewer that joins
	// mid-stream has no keyframe to decode, so it PLIs; without honoring it the
	// picture stays black until the next scheduled keyframe (the "only shows
	// after I reopen the viewer" symptom). Forcing a keyframe on PLI makes the
	// first frame appear almost immediately.
	if kf, ok := p.cfg.Source.(interface{ ForceKeyFrame() }); ok {
		go func() {
			buf := make([]byte, 1500)
			for {
				n, _, rtcpErr := sender.Read(buf)
				if rtcpErr != nil {
					return
				}
				pkts, perr := rtcp.Unmarshal(buf[:n])
				if perr != nil {
					continue
				}
				for _, pkt := range pkts {
					switch pkt.(type) {
					case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
						kf.ForceKeyFrame()
					}
				}
			}
		}()
	}

	// Inbound control data channel (admin -> device). The DEVICE creates it
	// here, BEFORE building the offer, so the data-channel m-line is present in
	// the offer's SDP. Previously the browser (the answerer) tried to create the
	// channel, but an SDP answer cannot introduce an m-line the offer omitted,
	// so the channel was never negotiated and NO input ever reached the device
	// (video worked, control silently did nothing). With the device as the
	// creator, the browser receives it via ondatachannel and input flows.
	inputHandler := func(msg webrtc.DataChannelMessage) {
		var ev InputEvent
		if json.Unmarshal(msg.Data, &ev) != nil {
			p.logger.Warn("remote-support input: bad json", zap.ByteString("data", msg.Data))
			return
		}
		if ev.Event == "control_state" && ev.Active != nil {
			p.logger.Info("remote-support control_state", zap.Bool("active", *ev.Active))
			sink.SetControlActive(*ev.Active)
			return
		}
		p.logger.Info("remote-support input event",
			zap.String("event", ev.Event), zap.Float64("x", ev.X), zap.Float64("y", ev.Y))
		sink.Apply(ev)
	}
	inputCh, err := pc.CreateDataChannel("openidx-input", &webrtc.DataChannelInit{Ordered: boolPtr(true)})
	if err != nil {
		return fmt.Errorf("create input channel: %w", err)
	}
	inputCh.OnOpen(func() {
		p.logger.Info("remote-support input channel opened (device-created)")
	})
	inputCh.OnMessage(inputHandler)
	// Also accept a browser-created channel (back-compat with older viewers that
	// still create their own) so input flows regardless of which side made it.
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		if dc.Label() != "openidx-input" {
			return
		}
		p.logger.Info("remote-support input channel opened (admin-created)")
		dc.OnMessage(inputHandler)
	})

	// Trickle ICE -> admin.
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		ci := c.ToJSON()
		var mid string
		if ci.SDPMid != nil {
			mid = *ci.SDPMid
		}
		var mline uint16
		if ci.SDPMLineIndex != nil {
			mline = *ci.SDPMLineIndex
		}
		p.writeEnvelope(conn, "ice", icePayload{Candidate: ci.Candidate, SDPMid: mid, SDPMLineIndex: mline})
	})

	connd := make(chan error, 1)
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		p.logger.Info("remote-support peer state", zap.String("state", s.String()))
		switch s {
		case webrtc.PeerConnectionStateConnected:
			// Force a keyframe as soon as the peer connects. A viewer that joins
			// an already-running encoder has no keyframe to decode, so it shows
			// black until the next scheduled one — the "I must reopen the viewer
			// to see the screen" symptom. Relying on the browser's PLI alone is
			// racy (it may fire before our RTCP reader is up). Pushing several
			// keyframes over the first ~1.5s guarantees the picture paints
			// promptly regardless of PLI timing.
			if kf, ok := p.cfg.Source.(interface{ ForceKeyFrame() }); ok {
				go func() {
					for i := 0; i < 4; i++ {
						kf.ForceKeyFrame()
						time.Sleep(400 * time.Millisecond)
					}
				}()
			}
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
			// Only Failed/Closed are terminal. Disconnected is TRANSIENT in
			// WebRTC — ICE frequently recovers it back to Connected after a
			// brief network blip. Treating Disconnected as fatal tore down a
			// working stream and triggered the reconnect loop, whose fresh
			// offer then confused the already-connected browser and blanked the
			// video ("works once, then black on the next connection"). Let ICE
			// try to recover; if it can't, it transitions to Failed and we exit.
			select {
			case connd <- fmt.Errorf("peer connection %s", s):
			default:
			}
		}
	})

	// DEVICE creates the offer (the browser is the answerer).
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("create offer: %w", err)
	}
	if err = pc.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("set local description: %w", err)
	}
	if err = p.writeEnvelope(conn, "sdp", sdpPayload{SDP: offer.SDP, Type: "offer"}); err != nil {
		return fmt.Errorf("send offer: %w", err)
	}

	// Start streaming frames once the source is ready. pumpDone is closed when
	// the pump goroutine has fully returned, so we can guarantee it is no longer
	// inside a (CGO/libvpx) NextFrame() read before anything closes the source.
	// Closing the encoder while a read is in flight deadlocks libvpx — that was
	// the "client hangs after the session ends, must Ctrl+C" bug.
	stopPump := make(chan struct{})
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		p.pumpFrames(track, stopPump)
	}()
	defer func() {
		close(stopPump)
		// Wait for the pump to stop touching the encoder, but bound the wait so
		// a wedged CGO read can never hang teardown forever (we'd rather leak a
		// frame read than freeze the whole client).
		select {
		case <-pumpDone:
		case <-time.After(2 * time.Second):
			p.logger.Warn("remote-support: frame pump did not stop in time")
		}
	}()

	// Signaling read loop.
	readErr := make(chan error, 1)
	go func() {
		for {
			var env envelope
			if err := conn.ReadJSON(&env); err != nil {
				readErr <- err
				return
			}
			switch env.Type {
			case "sdp":
				var sp sdpPayload
				if json.Unmarshal(env.Payload, &sp) == nil && sp.Type == "answer" {
					if e := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sp.SDP}); e != nil {
						p.logger.Warn("set remote answer failed", zap.Error(e))
					}
				}
			case "ice":
				var ip icePayload
				if json.Unmarshal(env.Payload, &ip) == nil && ip.Candidate != "" {
					mid := ip.SDPMid
					idx := ip.SDPMLineIndex
					_ = pc.AddICECandidate(webrtc.ICECandidateInit{Candidate: ip.Candidate, SDPMid: &mid, SDPMLineIndex: &idx})
				}
			}
		}
	}()

	select {
	case err = <-readErr:
		return err
	case err = <-connd:
		return err
	}
}

// pumpFrames reads encoded VP8 frames from the source and writes them to the
// track at the source's frame interval until stop.
func (p *Peer) pumpFrames(track *webrtc.TrackLocalStaticSample, stop <-chan struct{}) {
	src := p.cfg.Source
	interval := src.FrameInterval()
	if interval <= 0 {
		interval = 100 * time.Millisecond // 10 fps default
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			frame, err := src.NextFrame()
			if err != nil || len(frame) == 0 {
				continue
			}
			if err := track.WriteSample(media.Sample{Data: frame, Duration: interval}); err != nil {
				p.logger.Warn("write sample failed", zap.Error(err))
				return
			}
		}
	}
}

func (p *Peer) writeEnvelope(conn SignalConn, typ string, payload interface{}) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return conn.WriteJSON(envelope{Type: typ, Payload: raw})
}

// Close tears down the peer.
func (p *Peer) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if p.pc != nil {
		_ = p.pc.Close()
	}
	if p.cfg.Source != nil {
		p.cfg.Source.Close()
	}
}

// NewPeer builds a device peer from cfg.
func NewPeer(cfg PeerConfig) *Peer {
	return &Peer{cfg: cfg, logger: cfg.Logger}
}

// boolPtr returns a pointer to b, for optional webrtc init fields.
func boolPtr(b bool) *bool { return &b }
