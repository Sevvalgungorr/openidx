package remotesupport

import (
	"testing"
	"time"
)

// TestSourceHasVideo verifies the capability probe the peer uses to warn when a
// build can't stream video.
func TestSourceHasVideo(t *testing.T) {
	// The stub source (default/pure-Go build) reports no video.
	stub, err := NewScreenSource(10)
	if err != nil {
		t.Fatalf("NewScreenSource: %v", err)
	}
	defer stub.Close()
	// In the default build NewScreenSource returns the stub; assert it opts out.
	// (In a `-tags screenshare` build this would be the real capable source, so
	// only assert the negative when the stub is what we actually got.)
	if _, isStub := stub.(*stubVideoSource); isStub {
		if SourceHasVideo(stub) {
			t.Error("stub source should report HasVideo() == false")
		}
	}

	// A synthetic source (used by tests) emits frames, so it is treated as
	// video-capable by the default (unknown → capable) rule.
	syn := NewSyntheticSource(100*time.Millisecond, []byte{0x01})
	defer syn.Close()
	if !SourceHasVideo(syn) {
		t.Error("synthetic source should be treated as video-capable")
	}
}
