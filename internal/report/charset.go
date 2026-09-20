package report

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// ErrCharset reports an encoding that this parser will not decode. The label
// is never repeated back, because it comes from the input.
var ErrCharset = errors.New("xml: unsupported character encoding")

// charsetReader converts the few legacy encodings that senders still use. It
// never opens a network connection and it never opens a file.
func charsetReader(label string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "utf-8", "us-ascii":
		return input, nil
	case "iso-8859-1":
		return newByteMapReader(input, &latin1Table), nil
	case "windows-1252":
		return newByteMapReader(input, &cp1252Table), nil
	}
	return nil, ErrCharset
}

// byteMapReader converts a single-byte encoding to UTF-8 as it streams.
type byteMapReader struct {
	src   *bufio.Reader
	table *[256]rune
	pend  []byte
	buf   [4]byte
}

func newByteMapReader(r io.Reader, table *[256]rune) *byteMapReader {
	return &byteMapReader{src: bufio.NewReader(r), table: table}
}

func (m *byteMapReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(m.pend) > 0 {
			c := copy(p[n:], m.pend)
			n += c
			m.pend = m.pend[c:]
			continue
		}
		b, err := m.src.ReadByte()
		if err != nil {
			if n > 0 && errors.Is(err, io.EOF) {
				return n, nil
			}
			return n, err
		}
		l := utf8.EncodeRune(m.buf[:], m.table[b])
		m.pend = m.buf[:l]
	}
	return n, nil
}

var latin1Table = buildLatin1Table()

var cp1252Table = buildCP1252Table()

func buildLatin1Table() [256]rune {
	var t [256]rune
	for i := range t {
		t[i] = rune(i)
	}
	return t
}

func buildCP1252Table() [256]rune {
	t := buildLatin1Table()
	high := [32]rune{
		0x20AC, 0xFFFD, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
		0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0xFFFD, 0x017D, 0xFFFD,
		0xFFFD, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
		0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0xFFFD, 0x017E, 0x0178,
	}
	for i, r := range high {
		t[0x80+i] = r
	}
	return t
}
