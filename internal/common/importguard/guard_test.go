// Package importguard holds no code. It exists for one test: the module's
// production import graph must not contain test-only machinery.
//
// This has now been a real bug twice. internal/oauth/test_helper.go and
// internal/audit/test_helper.go were each written without the _test.go suffix,
// so Go compiled them into the production package. The oauth one dragged
// `testing` and miniredis into the production graph and broke govulncheck; the
// audit one put `testing` into seven shipped service binaries — access,
// admin-api, audit, governance, identity, oauth and provisioning — because
// internal/audit is imported by all of them.
//
// Both were found by accident while looking for something else. Neither was
// caught by the build, by vet, or by any test, because nothing is wrong with
// the code — only with the filename. A guard is the only thing that catches
// the third one.
package importguard

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// testOnlyImports are packages that have no business in a production binary.
// `testing` registers flags and pulls in the whole test harness; the container
// and mock libraries drag in Docker clients and a Redis implementation.
var testOnlyImports = []string{
	"testing",
	"testing/quick",
	"github.com/alicebob/miniredis",
	"github.com/testcontainers/testcontainers-go",
	"github.com/stretchr/testify",
	"github.com/DATA-DOG/go-sqlmock",
}

// sharedTestSupport are packages that deliberately hold test helpers in
// non-_test files, so that suites in many packages can share one bootstrap
// instead of each copying it. They are allowed to import test-only machinery
// (rule 1 skips them) precisely because rule 2 proves nothing in production
// reaches them.
var sharedTestSupport = []string{
	"github.com/openidx/openidx/internal/common/testsupport",
	"github.com/openidx/openidx/internal/common/testutil",
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the test's working directory")
		}
		dir = parent
	}
}

// productionFiles returns every .go file that is compiled into the package
// proper — i.e. everything except _test.go files, vendored code and testdata.
func productionFiles(t *testing.T, root string) []string {
	t.Helper()

	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "testdata", "node_modules", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(files) < 100 {
		// If the walk silently found almost nothing, every assertion below
		// would pass vacuously.
		t.Fatalf("only found %d production .go files; the walk is not covering the repo", len(files))
	}
	return files
}

func imports(t *testing.T, path string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []string
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out
}

func matches(imp string, list []string) bool {
	for _, want := range list {
		if imp == want || strings.HasPrefix(imp, want+"/") {
			return true
		}
	}
	return false
}

func TestProductionFilesDoNotImportTestOnlyPackages(t *testing.T) {
	root := repoRoot(t)

	for _, path := range productionFiles(t, root) {
		rel, _ := filepath.Rel(root, path)
		// The shared test-support packages are the documented exception; rule 2
		// below is what keeps them out of the binaries.
		if matches("github.com/openidx/openidx/"+filepath.ToSlash(filepath.Dir(rel)), sharedTestSupport) {
			continue
		}
		if rel == filepath.Join("internal", "common", "importguard", "guard_test.go") {
			continue
		}

		for _, imp := range imports(t, path) {
			if matches(imp, testOnlyImports) {
				t.Errorf("%s imports %q but is not a _test.go file.\n"+
					"Go compiles it into the package proper, so %q ends up in every binary that "+
					"imports this package. If it is a test helper, rename it to *_test.go.",
					rel, imp, imp)
			}
		}
	}
}

func TestProductionFilesDoNotImportSharedTestSupport(t *testing.T) {
	// The rule that actually protects the shipped binaries. internal/common/
	// testsupport imports testcontainers and internal/common/testutil imports
	// miniredis; both say so in their package docs. That is fine only for as
	// long as nothing outside a _test.go file imports them.
	root := repoRoot(t)

	for _, path := range productionFiles(t, root) {
		rel, _ := filepath.Rel(root, path)
		dir := "github.com/openidx/openidx/" + filepath.ToSlash(filepath.Dir(rel))
		if matches(dir, sharedTestSupport) {
			continue // the packages themselves
		}

		for _, imp := range imports(t, path) {
			if matches(imp, sharedTestSupport) {
				t.Errorf("%s imports the test-support package %q from a non-test file.\n"+
					"That pulls its container/mock dependencies into the production import "+
					"graph. Import it from a _test.go file instead.", rel, imp)
			}
		}
	}
}
