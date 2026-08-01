// Package testsupport holds helpers shared by the container-backed test suites.
//
// It is a normal (non-_test) package so that suites in a dozen different
// packages can import it instead of each keeping its own copy of the same
// bootstrap. That has one consequence worth stating: anything imported here
// lands in the module's production import graph. testcontainers-go pulls in the
// Docker client, which carries its own advisories, so importing it here would
// make govulncheck report the whole Docker surface as reachable from shipped
// code. Hence the callback below — the caller names the container type and does
// the starting, and testcontainers stays confined to _test.go files where it
// belongs.
package testsupport

import "testing"

// RunOrSkip invokes start and skips the test when no container runtime is
// reachable.
//
// The recover() is load-bearing rather than defensive padding. testcontainers-go
// resolves the Docker host through MustExtractDockerHost, which PANICS when
// there is no runtime instead of returning an error. Every suite here was
// written as
//
//	container, err := testcontainers.GenericContainer(...)
//	if err != nil { t.Skipf(...) }
//
// and several even carry a comment promising they skip when Docker is missing —
// but that branch is unreachable: the panic escapes first and takes down the
// whole test binary, so one missing runtime turns every test in the package red,
// including the ones that never wanted a database.
//
// That was survivable while the unit-test CI job swallowed its own exit code.
// Now that the job is a real gate, a runtime hiccup on a runner would fail
// packages that have nothing to do with containers, and the gate would teach
// people to ignore it. Skipping keeps the signal honest: a red package means a
// real regression.
func RunOrSkip[T any](t *testing.T, what string, start func() (T, error)) T {
	t.Helper()

	var out T
	func() {
		defer func() {
			// Only a panic lands here with a non-nil value; the t.Skipf calls
			// unwind via runtime.Goexit, which recover() does not intercept.
			if r := recover(); r != nil {
				t.Skipf("no container runtime available: %v", r)
			}
		}()
		var err error
		if out, err = start(); err != nil {
			t.Skipf("could not start container %s: %v", what, err)
		}
	}()
	return out
}
