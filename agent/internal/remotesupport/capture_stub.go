//go:build !screenshare

package remotesupport

import "time"

// NewScreenSource returns a no-op capture source in the default (pure-Go) build.
// The agent can still negotiate a session and exchange signaling — it simply
// sends no video frames. The real capture+VP8 path is compiled in with the
// `screenshare` build tag (CGO/libvpx), used by the packaged Windows build.
func NewScreenSource(fps int) (VideoSource, error) {
	interval := time.Second / 10
	if fps > 0 {
		interval = time.Second / time.Duration(fps)
	}
	return &stubVideoSource{interval: interval}, nil
}

type stubVideoSource struct{ interval time.Duration }

func (s *stubVideoSource) NextFrame() ([]byte, error)   { return nil, nil }
func (s *stubVideoSource) FrameInterval() time.Duration { return s.interval }
func (s *stubVideoSource) Close()                       {}

// HasVideo reports that this build sends no frames, so a peer can log a clear
// diagnostic (and the operator understands why the viewer shows no screen).
func (s *stubVideoSource) HasVideo() bool { return false }
