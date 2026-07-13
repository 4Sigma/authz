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

// TestNoThirdPartyImports keeps the library dependency-free: the core authz
// package may import only the standard library, so that adopting it never
// drags dependencies into an application. The only exception is the optional
// zerologadapter subpackage, which exists precisely to bridge zerolog and may
// import it (applications not using zerolog never link it).
func TestNoThirdPartyImports(t *testing.T) {
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
			if allowedImport(path, target) {
				continue
			}
			t.Errorf("%s imports %q: the authz core must depend on the standard library only", path, target)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func allowedImport(file, target string) bool {
	// Standard library packages have no dot in their first path element.
	if first, _, _ := strings.Cut(target, "/"); !strings.Contains(first, ".") {
		return true
	}
	// The library may import itself (tests do).
	if target == "github.com/4Sigma/authz" || strings.HasPrefix(target, "github.com/4Sigma/authz/") {
		return true
	}
	// zerologadapter exists to bridge zerolog, so it alone may import it.
	if strings.HasPrefix(filepath.ToSlash(file), "zerologadapter/") {
		return strings.HasPrefix(target, "github.com/rs/zerolog")
	}
	return false
}
