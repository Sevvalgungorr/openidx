package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// TestCapabilitiesCommand runs the `capabilities` subcommand and asserts it
// emits well-formed JSON with a screen_capture field. In the default (pure-Go)
// test build the value is false; a `-tags screenshare` build would report true.
// This is the runtime signal CI uses to prove the packaged agent can actually
// capture the screen (not just that it compiled).
func TestCapabilitiesCommand(t *testing.T) {
	// Capture stdout while the command runs (it writes JSON to os.Stdout).
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	runErr := capabilitiesCmd.RunE(capabilitiesCmd, nil)

	_ = w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	if runErr != nil {
		t.Fatalf("capabilities RunE: %v", runErr)
	}

	var out struct {
		Version       string `json:"version"`
		Commit        string `json:"commit"`
		ScreenCapture *bool  `json:"screen_capture"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("capabilities output is not valid JSON: %v\n%s", err, buf.String())
	}
	if out.ScreenCapture == nil {
		t.Fatal("capabilities output missing screen_capture field")
	}
	// Default (no screenshare tag) test build: capture is stubbed → false.
	if *out.ScreenCapture {
		t.Log("screen_capture=true (screenshare-tagged build)")
	} else {
		t.Log("screen_capture=false (default/pure-Go build)")
	}
}
