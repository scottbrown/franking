package archive

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/scottbrown/franking/internal/safe"
)

// Walk limits.
const (
	MaxWalkDepth = 8
	MaxWalkFiles = 10000
)

// WalkOptions controls the directory scan.
type WalkOptions struct {
	Recurse  bool
	MaxDepth int
	MaxFiles int
}

// DefaultWalkOptions returns the built-in walk options.
func DefaultWalkOptions() WalkOptions {
	return WalkOptions{MaxDepth: MaxWalkDepth, MaxFiles: MaxWalkFiles}
}

// Walk lists the candidate report files under root. It uses Lstat on every
// entry and takes regular files only, so a symlink, a device, a FIFO, and a
// socket are all skipped and never followed.
func Walk(root string, opt WalkOptions) (files []string, warnings []string, err error) {
	if opt.MaxDepth <= 0 {
		opt.MaxDepth = MaxWalkDepth
	}
	if opt.MaxFiles <= 0 {
		opt.MaxFiles = MaxWalkFiles
	}
	fi, err := os.Stat(root)
	if err != nil {
		return nil, nil, err
	}
	if !fi.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a directory", safe.FileName(root))
	}
	w := &walker{opt: opt}
	w.dir(root, 1)
	sort.Strings(w.files)
	return w.files, w.warnings, nil
}

type walker struct {
	opt      WalkOptions
	files    []string
	warnings []string
	capped   bool
}

func (w *walker) warn(format string, args ...any) {
	w.warnings = append(w.warnings, safe.Reason(fmt.Sprintf(format, args...)))
}

func (w *walker) dir(path string, depth int) {
	entries, err := os.ReadDir(path)
	if err != nil {
		w.warn("cannot read directory %s: %s", safe.FileName(path), reasonOf(err))
		return
	}
	for _, entry := range entries {
		if w.capped {
			return
		}
		full := filepath.Join(path, entry.Name())
		info, err := os.Lstat(full)
		if err != nil {
			w.warn("skipped %s: cannot stat", safe.FileName(entry.Name()))
			continue
		}
		mode := info.Mode()
		switch {
		case mode&os.ModeSymlink != 0:
			w.warn("skipped %s: symlink", safe.FileName(entry.Name()))
		case mode.IsDir():
			if !w.opt.Recurse {
				continue
			}
			if depth >= w.opt.MaxDepth {
				w.warn("skipped %s: directory deeper than %d levels",
					safe.FileName(entry.Name()), w.opt.MaxDepth)
				continue
			}
			w.dir(full, depth+1)
		case !mode.IsRegular():
			w.warn("skipped %s: not a regular file", safe.FileName(entry.Name()))
		default:
			w.file(full, entry.Name())
		}
	}
}

func (w *walker) file(full, name string) {
	if !hasReportExt(name) {
		return
	}
	if !readable(full) {
		w.warn("skipped %s: no read permission", safe.FileName(name))
		return
	}
	if len(w.files) >= w.opt.MaxFiles {
		if !w.capped {
			w.warn("stopped after %d files", w.opt.MaxFiles)
			w.capped = true
		}
		return
	}
	w.files = append(w.files, full)
}

func hasReportExt(name string) bool {
	return slices.Contains(Extensions(), strings.ToLower(filepath.Ext(name)))
}

// readable reports whether the file can be opened for reading. Permissions
// are never changed.
func readable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func reasonOf(err error) string {
	if os.IsPermission(err) {
		return "no read permission"
	}
	return "unreadable"
}
