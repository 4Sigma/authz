package authz_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNoApplicationImports keeps the library application-agnostic: no file in
// authz (or its subpackages) may import a LabCatch package, so that the
// library can be extracted into its own module at zero cost. Only imports of
// the library itself are allowed from the current module.
func TestNoApplicationImports(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			target, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if strings.HasPrefix(target, "labcatch/") && !strings.HasPrefix(target, "labcatch/authz") {
				t.Errorf("%s imports %q: the authz library must not depend on the application", path, target)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
