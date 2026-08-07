package handlers

import (
	"testing"

	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

// TestBrandingURLValidator guards QA 10.6: the branding logo/favicon fields must
// accept a same-origin relative path (the platform's own defaults are
// "/assets/logo.png") as well as absolute http(s) URLs, and reject garbage. The
// old "url" binding tag rejected relative paths, so saving the server's own
// default settings failed with a 400.
func TestBrandingURLValidator(t *testing.T) {
	registerBrandingValidators()

	v, ok := binding.Validator.Engine().(*validator.Validate)
	if !ok {
		t.Fatal("gin binding validator is not a *validator.Validate")
	}

	cases := []struct {
		in   string
		want bool
	}{
		{"", true},                                 // empty (omitempty pairs with this)
		{"/assets/logo.png", true},                 // root-relative same-origin
		{"/favicon.ico", true},                     // root-relative
		{"https://cdn.example.com/logo.png", true}, // absolute https
		{"http://example.com/logo.png", true},      // absolute http
		{"assets/logo.png", false},                 // relative but not root-anchored
		{"ftp://example.com/logo.png", false},      // wrong scheme
		{"javascript:alert(1)", false},             // not a path or http(s) URL
		{"not a url", false},                       // garbage
	}

	for _, c := range cases {
		err := v.Var(c.in, "omitempty,httpurl_or_path")
		got := err == nil
		if got != c.want {
			t.Errorf("httpurl_or_path(%q) = %v (err=%v), want %v", c.in, got, err, c.want)
		}
	}
}

// TestUpdateSettingsAcceptsDefaultBranding is the end-to-end guard: the branding
// section the server itself returns by default (relative asset paths) must pass
// binding validation. This is the exact round-trip that failed in QA 10.6.
func TestUpdateSettingsAcceptsDefaultBranding(t *testing.T) {
	registerBrandingValidators()
	h := &SettingsHandler{}
	def := h.getDefaultBrandingSection()

	v, ok := binding.Validator.Engine().(*validator.Validate)
	if !ok {
		t.Fatal("gin binding validator is not a *validator.Validate")
	}
	if err := v.Struct(def); err != nil {
		t.Fatalf("default branding section must validate, got: %v", err)
	}
}
