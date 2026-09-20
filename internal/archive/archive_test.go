package archive

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const smallReport = `<?xml version="1.0" encoding="UTF-8"?>
<feedback><report_metadata><org_name>example.ca</org_name></report_metadata></feedback>`

func TestDetectKind(t *testing.T) {
	tests := []struct {
		name string
		head []byte
		file string
		want Kind
	}{
		{"zip by content", []byte("PK\x03\x04rest"), "report.bin", KindZip},
		{"gzip by content", []byte{0x1f, 0x8b, 0x08, 0x00}, "report.bin", KindGzip},
		{"content beats a wrong extension", []byte("PK\x03\x04"), "report.xml", KindZip},
		{"gzip content in a zip name", []byte{0x1f, 0x8b}, "report.zip", KindGzip},
		{"xml by extension", []byte("<feedback>"), "report.xml", KindXML},
		{"zip by extension only", nil, "report.zip", KindZip},
		{"gz by extension only", nil, "report.gz", KindGzip},
		{"xml by shape", []byte("  <feedback>"), "report.bin", KindXML},
		{"unknown", []byte("garbage"), "report.bin", KindUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectKind(tc.head, tc.file); got != tc.want {
				t.Fatalf("DetectKind() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOpenContainers(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "plain.xml"), []byte(smallReport))
	writeFile(t, filepath.Join(dir, "report.gz"), gzipBytes(t, []byte(smallReport)))
	writeFile(t, filepath.Join(dir, "report.zip"), zipBytes(t, "report.xml", []byte(smallReport)))
	// A zip that a sender mislabelled as .xml.
	writeFile(t, filepath.Join(dir, "mislabelled.xml"), zipBytes(t, "report.xml", []byte(smallReport)))

	tests := []struct {
		file string
		want Kind
	}{
		{"plain.xml", KindXML},
		{"report.gz", KindGzip},
		{"report.zip", KindZip},
		{"mislabelled.xml", KindZip},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			src, err := Open(filepath.Join(dir, tc.file), DefaultLimits())
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer src.Close()
			if src.Kind != tc.want {
				t.Errorf("kind = %q, want %q", src.Kind, tc.want)
			}
			got, err := io.ReadAll(src)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != smallReport {
				t.Errorf("content = %q", got)
			}
		})
	}
}

func TestOpenRejects(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "big.xml"), bytes.Repeat([]byte("a"), 4096))
	writeFile(t, filepath.Join(dir, "bomb.gz"), gzipBomb(t))
	writeFile(t, filepath.Join(dir, "liar.zip"), lyingZip(t))
	writeFile(t, filepath.Join(dir, "many.zip"), manyMemberZip(t, 5000))
	writeFile(t, filepath.Join(dir, "no-xml.zip"), zipBytes(t, "readme.txt", []byte("nothing here")))
	writeFile(t, filepath.Join(dir, "damaged.zip"), []byte("PK\x03\x04 and then nonsense"))
	writeFile(t, filepath.Join(dir, "damaged.gz"), []byte{0x1f, 0x8b, 0x08, 0x00, 0x00})
	writeFile(t, filepath.Join(dir, "unknown.bin"), []byte("neither xml nor an archive"))

	tests := []struct {
		name     string
		file     string
		limits   Limits
		wantErrs []error
	}{
		{"file above the size limit", "big.xml",
			Limits{MaxFileSize: 1024}, []error{ErrTooLarge}},
		{"gzip bomb", "bomb.gz", DefaultLimits(), []error{ErrRatio}},
		// A false UncompressedSize64 is caught either by our guards or by
		// the zip reader's own size check. Both are a clean rejection.
		{"zip with a false declared size", "liar.zip", DefaultLimits(),
			[]error{ErrRatio, ErrExpandsTooBig, ErrBadContainer}},
		{"zip with too many members", "many.zip", DefaultLimits(), []error{ErrTooManyMembers}},
		{"zip with no xml member", "no-xml.zip", DefaultLimits(), []error{ErrNoXMLMember}},
		{"damaged zip", "damaged.zip", DefaultLimits(), []error{ErrBadContainer}},
		{"damaged gzip", "damaged.gz", DefaultLimits(), []error{ErrBadContainer}},
		{"unknown container", "unknown.bin", DefaultLimits(), []error{ErrUnknownKind}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var read int64
			src, err := Open(filepath.Join(dir, tc.file), tc.limits)
			if err == nil {
				// Some limits only fire once the stream is read.
				defer src.Close()
				read, err = io.Copy(io.Discard, src)
			}
			if !matchesAny(err, tc.wantErrs) {
				t.Fatalf("error = %v, want one of %v", err, tc.wantErrs)
			}
			if read > DefaultMaxXMLSize {
				t.Fatalf("read %d bytes before the rejection", read)
			}
			assertPlainMessage(t, err)
		})
	}
}

func matchesAny(err error, wants []error) bool {
	for _, want := range wants {
		if errors.Is(err, want) {
			return true
		}
	}
	return false
}

func TestSizeLimitStopsAnExpandingStream(t *testing.T) {
	dir := t.TempDir()
	// Highly compressible but under the ratio limit for its size, so the
	// byte limit is the check that has to fire.
	writeFile(t, filepath.Join(dir, "wide.gz"), gzipBytes(t, bytes.Repeat([]byte("abcdefghij"), 300000)))

	src, err := Open(filepath.Join(dir, "wide.gz"), Limits{MaxXMLSize: 64 * 1024, MaxRatio: 1e9})
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	n, err := io.Copy(io.Discard, src)
	if !errors.Is(err, ErrExpandsTooBig) {
		t.Fatalf("error = %v, want %v", err, ErrExpandsTooBig)
	}
	if n > 64*1024 {
		t.Fatalf("read %d bytes past the limit", n)
	}
}

func TestZipMemberNameNeverReachesTheFilesystem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "slip.zip")
	writeFile(t, path, zipBytes(t, "../../../etc/passwd.xml", []byte(smallReport)))

	before := treeOf(t, dir)
	src, err := Open(path, DefaultLimits())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer src.Close()
	got, err := io.ReadAll(src)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != smallReport {
		t.Fatalf("content = %q", got)
	}
	if after := treeOf(t, dir); after != before {
		t.Fatalf("the directory changed:\nbefore %s\nafter  %s", before, after)
	}
	if _, err := os.Lstat(filepath.Join(dir, "etc", "passwd.xml")); err == nil {
		t.Fatal("a file was written from the member name")
	}
}

func TestHostileFilesStayUnderTheMemoryCeiling(t *testing.T) {
	const ceiling = 256 << 20

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "bomb.gz"), gzipBomb(t))
	writeFile(t, filepath.Join(dir, "liar.zip"), lyingZip(t))
	writeFile(t, filepath.Join(dir, "many.zip"), manyMemberZip(t, 5000))

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Run(e.Name(), func(t *testing.T) {
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)

			src, err := Open(filepath.Join(dir, e.Name()), DefaultLimits())
			if err == nil {
				io.Copy(io.Discard, src)
				src.Close()
			}
			runtime.ReadMemStats(&after)

			if after.HeapAlloc > ceiling {
				t.Fatalf("heap at %d bytes, above the %d ceiling", after.HeapAlloc, ceiling)
			}
			if grew := after.TotalAlloc - before.TotalAlloc; grew > ceiling {
				t.Fatalf("allocated %d bytes for one hostile file", grew)
			}
		})
	}
}

func TestWalkTakesOnlyRegularReportFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.xml"), []byte(smallReport))
	writeFile(t, filepath.Join(dir, "b.zip"), zipBytes(t, "r.xml", []byte(smallReport)))
	writeFile(t, filepath.Join(dir, "c.gz"), gzipBytes(t, []byte(smallReport)))
	writeFile(t, filepath.Join(dir, "notes.txt"), []byte("ignored"))
	writeFile(t, filepath.Join(dir, "archive.tar"), []byte("ignored"))

	if err := os.Symlink("/dev/zero", filepath.Join(dir, "zero.xml")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(sub, "deep.xml"), []byte(smallReport))

	files, warnings, err := Walk(dir, DefaultWalkOptions())
	if err != nil {
		t.Fatal(err)
	}
	if got := names(files); strings.Join(got, ",") != "a.xml,b.zip,c.gz" {
		t.Fatalf("files = %v", got)
	}
	if !containsSubstring(warnings, "symlink") {
		t.Fatalf("want a warning about the symlink, got %v", warnings)
	}

	recursed, _, err := Walk(dir, WalkOptions{Recurse: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(recursed); strings.Join(got, ",") != "a.xml,b.zip,c.gz,deep.xml" {
		t.Fatalf("recursive files = %v", got)
	}
}

func TestWalkDepthLimit(t *testing.T) {
	root := t.TempDir()
	dir := root
	for range 12 {
		dir = filepath.Join(dir, "d")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, "r.xml"), []byte(smallReport))
	}
	files, warnings, err := Walk(root, WalkOptions{Recurse: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != MaxWalkDepth-1 {
		t.Fatalf("found %d files, want %d", len(files), MaxWalkDepth-1)
	}
	if !containsSubstring(warnings, "deeper than") {
		t.Fatalf("want a depth warning, got %v", warnings)
	}
}

func TestWalkFileCap(t *testing.T) {
	dir := t.TempDir()
	for i := range 20 {
		writeFile(t, filepath.Join(dir, string(rune('a'+i))+".xml"), []byte(smallReport))
	}
	files, warnings, err := Walk(dir, WalkOptions{MaxFiles: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 5 {
		t.Fatalf("found %d files, want 5", len(files))
	}
	if !containsSubstring(warnings, "stopped after") {
		t.Fatalf("want a cap warning, got %v", warnings)
	}
}

func TestWalkRejectsANonDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.xml")
	writeFile(t, path, []byte(smallReport))
	if _, _, err := Walk(path, DefaultWalkOptions()); err == nil {
		t.Fatal("want an error for a file argument")
	}
}

// --- helpers -------------------------------------------------------------

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func gzipBytes(t *testing.T, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zipBytes(t *testing.T, member string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: member, Method: zip.Deflate})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// gzipBomb builds roughly 1 MB of gzip that expands past 1 GB.
func gzipBomb(t *testing.T) []byte {
	t.Helper()
	const total = 1 << 30
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	for written := 0; written < total; written += len(chunk) {
		if _, err := zw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() > 4<<20 {
		t.Fatalf("bomb is %d bytes compressed, want about 1 MB", buf.Len())
	}
	return buf.Bytes()
}

// lyingZip builds a zip whose central directory declares a tiny uncompressed
// size and whose member then gives a very large stream.
func lyingZip(t *testing.T) []byte {
	t.Helper()
	payload := make([]byte, 256<<20)

	var raw bytes.Buffer
	fw, err := flate.NewWriter(&raw, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{
		Name:               "report.xml",
		Method:             zip.Deflate,
		CRC32:              crc32.ChecksumIEEE(payload),
		CompressedSize64:   uint64(raw.Len()),
		UncompressedSize64: 1024, // the lie
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func manyMemberZip(t *testing.T, members int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := range members {
		w, err := zw.Create("member-" + itoa(i) + ".xml")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func names(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Base(p)
	}
	return out
}

func containsSubstring(values []string, want string) bool {
	for _, v := range values {
		if strings.Contains(v, want) {
			return true
		}
	}
	return false
}

func treeOf(t *testing.T, dir string) string {
	t.Helper()
	var out []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(out, "\n")
}

func assertPlainMessage(t *testing.T, err error) {
	t.Helper()
	msg := err.Error()
	for i := range len(msg) {
		if msg[i] < 0x20 {
			t.Fatalf("error message holds a control byte: %q", msg)
		}
	}
}
