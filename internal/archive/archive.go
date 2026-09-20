// Package archive detects the container of an input file and returns a
// bounded reader over the XML inside it. Nothing is ever written to disk and
// an archive member name is never used as a path.
package archive

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// Kind is the container of an input file.
type Kind string

// The containers that this tool reads.
const (
	KindZip     Kind = "zip"
	KindGzip    Kind = "gzip"
	KindXML     Kind = "xml"
	KindUnknown Kind = "unknown"
)

// Fixed limits that have no flag.
const (
	MaxZipMembers = 16
	ratioFloor    = 4096 // ignore the ratio until this many compressed bytes
)

// Default limits for the flags that can raise them.
const (
	DefaultMaxFileSize int64   = 50 << 20
	DefaultMaxXMLSize  int64   = 64 << 20
	DefaultMaxRatio    float64 = 200
)

// Limits bound the size and the expansion of one input file.
type Limits struct {
	MaxFileSize int64
	MaxXMLSize  int64
	MaxRatio    float64
}

// DefaultLimits returns the built-in limits.
func DefaultLimits() Limits {
	return Limits{
		MaxFileSize: DefaultMaxFileSize,
		MaxXMLSize:  DefaultMaxXMLSize,
		MaxRatio:    DefaultMaxRatio,
	}
}

// Errors that a hostile or unusable file produces. Each one is a complete
// sentence about the problem and holds no byte from the input.
var (
	ErrTooLarge       = errors.New("file is larger than the maximum input size")
	ErrExpandsTooBig  = errors.New("report expands beyond the maximum decompressed size")
	ErrRatio          = errors.New("compression ratio is above the maximum")
	ErrTooManyMembers = errors.New("zip holds more members than the limit")
	ErrNoXMLMember    = errors.New("zip holds no .xml member")
	ErrNotRegular     = errors.New("not a regular file")
	ErrUnknownKind    = errors.New("file is not a zip, a gzip, or an xml document")
	ErrBadContainer   = errors.New("container is damaged")
)

var (
	zipMagic  = []byte{'P', 'K', 0x03, 0x04}
	gzipMagic = []byte{0x1f, 0x8b}
)

// Extensions returns the file extensions that the walk accepts.
func Extensions() []string { return []string{".zip", ".gz", ".xml"} }

// DetectKind decides the container from the leading bytes, and falls back to
// the file extension when the content says nothing. Some senders give an
// extension that does not match the content, so content wins.
func DetectKind(head []byte, name string) Kind {
	switch {
	case bytes.HasPrefix(head, zipMagic):
		return KindZip
	case bytes.HasPrefix(head, gzipMagic):
		return KindGzip
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".zip":
		return KindZip
	case ".gz":
		return KindGzip
	case ".xml":
		return KindXML
	}
	if looksLikeXML(head) {
		return KindXML
	}
	return KindUnknown
}

func looksLikeXML(head []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(head, " \t\r\n\xef\xbb\xbf"), []byte("<"))
}

// Source is an open, bounded XML stream over one input file.
type Source struct {
	Kind   Kind
	reader io.Reader
	closes []io.Closer
}

// Read gives the next bytes of the XML document.
func (s *Source) Read(p []byte) (int, error) { return s.reader.Read(p) }

// Close releases the file and any decompressor over it.
func (s *Source) Close() error {
	var err error
	for i := len(s.closes) - 1; i >= 0; i-- {
		if cerr := s.closes[i].Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// Open returns a bounded reader over the XML document inside path. The caller
// must close the result. The file is opened read-only and is never modified.
func Open(path string, lim Limits) (*Source, error) {
	lim = withDefaults(lim)

	// Check the on-disk size before opening anything.
	li, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !li.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	if li.Size() > lim.MaxFileSize {
		return nil, ErrTooLarge
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, ErrNotRegular
	}
	if fi.Size() > lim.MaxFileSize {
		f.Close()
		return nil, ErrTooLarge
	}

	head := make([]byte, 4)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		f.Close()
		return nil, ErrBadContainer
	}
	head = head[:n]
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, ErrBadContainer
	}

	kind := DetectKind(head, path)
	var src *Source
	switch kind {
	case KindXML:
		src, err = openXML(f, lim)
	case KindGzip:
		src, err = openGzip(f, lim)
	case KindZip:
		src, err = openZip(f, fi.Size(), lim)
	default:
		err = ErrUnknownKind
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return src, nil
}

func withDefaults(lim Limits) Limits {
	d := DefaultLimits()
	if lim.MaxFileSize <= 0 {
		lim.MaxFileSize = d.MaxFileSize
	}
	if lim.MaxXMLSize <= 0 {
		lim.MaxXMLSize = d.MaxXMLSize
	}
	if lim.MaxRatio <= 0 {
		lim.MaxRatio = d.MaxRatio
	}
	return lim
}

func openXML(f *os.File, lim Limits) (*Source, error) {
	return &Source{
		Kind:   KindXML,
		reader: newGuard(f, nil, lim),
		closes: []io.Closer{f},
	}, nil
}

func openGzip(f *os.File, lim Limits) (*Source, error) {
	counter := &counter{}
	zr, err := gzip.NewReader(&countingReader{src: f, n: counter})
	if err != nil {
		return nil, ErrBadContainer
	}
	return &Source{
		Kind:   KindGzip,
		reader: newGuard(zr, counter, lim),
		closes: []io.Closer{zr, f},
	}, nil
}

func openZip(f *os.File, size int64, lim Limits) (*Source, error) {
	counter := &counter{}
	ra := &countingReaderAt{src: f, n: counter}
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return nil, ErrBadContainer
	}
	if len(zr.File) > MaxZipMembers {
		return nil, ErrTooManyMembers
	}
	for _, member := range zr.File {
		// The member name is display data only. It is never joined to a
		// path, so "../../../etc/passwd" cannot escape anywhere.
		if !strings.HasSuffix(strings.ToLower(member.Name), ".xml") {
			continue
		}
		// A declared size is attacker-controlled. Use it for early
		// rejection only; the guard below is what actually holds.
		if member.UncompressedSize64 > uint64(lim.MaxXMLSize) {
			return nil, ErrExpandsTooBig
		}
		rc, err := member.Open()
		if err != nil {
			return nil, ErrBadContainer
		}
		return &Source{
			Kind:   KindZip,
			reader: newGuard(rc, counter, lim),
			closes: []io.Closer{rc, f},
		}, nil
	}
	return nil, ErrNoXMLMember
}

// counter holds a compressed byte total that a reader updates as it goes.
type counter struct{ v atomic.Int64 }

func (c *counter) add(n int) { c.v.Add(int64(n)) }
func (c *counter) load() int64 {
	if c == nil {
		return 0
	}
	return c.v.Load()
}

type countingReader struct {
	src io.Reader
	n   *counter
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	c.n.add(n)
	return n, err
}

type countingReaderAt struct {
	src io.ReaderAt
	n   *counter
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.src.ReadAt(p, off)
	c.n.add(n)
	return n, err
}

// guard stops a decompressed stream that grows past the size limit or that
// expands faster than the ratio limit. Both checks fire during the read.
type guard struct {
	src        io.Reader
	compressed *counter
	maxOut     int64
	maxRatio   float64
	out        int64
}

func newGuard(r io.Reader, c *counter, lim Limits) *guard {
	return &guard{src: r, compressed: c, maxOut: lim.MaxXMLSize, maxRatio: lim.MaxRatio}
}

func (g *guard) Read(p []byte) (int, error) {
	// Read at most one byte past the limit. That extra byte is the signal
	// that the stream is too large.
	room := g.maxOut - g.out + 1
	if room <= 0 {
		return 0, ErrExpandsTooBig
	}
	if int64(len(p)) > room {
		p = p[:room]
	}
	n, err := g.src.Read(p)
	g.out += int64(n)
	if g.out > g.maxOut {
		return 0, ErrExpandsTooBig
	}
	if c := g.compressed.load(); c >= ratioFloor && float64(g.out)/float64(c) > g.maxRatio {
		return 0, ErrRatio
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return n, fmt.Errorf("%w", ErrBadContainer)
	}
	return n, err
}
