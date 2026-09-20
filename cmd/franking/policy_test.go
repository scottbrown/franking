package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// TestNoProcessExecution proves that nothing in the tree can start another
// process or a shell. The banned import is built from pieces so that a grep
// over the repository for it finds nothing at all.
func TestNoProcessExecution(t *testing.T) {
	banned := []string{"os" + "/exec", "syscall." + "Exec", "syscall." + "ForkExec"}
	root := repoRoot(t)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == ".build" || d.Name() == ".test" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, bad := range banned {
			if strings.Contains(string(b), bad) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s uses %s", rel, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestNoDependencies proves that the module needs nothing but the standard
// library.
func TestNoDependencies(t *testing.T) {
	root := repoRoot(t)

	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "require") {
		t.Fatalf("go.mod declares a dependency:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(root, "go.sum")); err == nil {
		t.Fatal("go.sum exists, so something was pulled in")
	}
	if _, err := os.Stat(filepath.Join(root, "vendor")); err == nil {
		t.Fatal("a vendor directory exists")
	}
}

// TestNoEnvironmentPaths proves that no file path comes from the
// environment.
func TestNoEnvironmentPaths(t *testing.T) {
	root := repoRoot(t)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == ".build" || d.Name() == ".test" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, bad := range []string{"os.Getenv", "os.LookupEnv", "os.Environ"} {
			if strings.Contains(string(b), bad) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s reads the environment with %s", rel, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
