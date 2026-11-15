package console

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"rsc.io/qr"

	"github.com/chris/aivan-authz/internal/policy"
)

// QRStyle selects how an enrollment code is drawn for a terminal.
//
// The default is QRAuto, so an operator who runs the command at a terminal sees
// the code as a scannable square without asking for it, and a caller that pipes
// the output to a file gets the text it has always got. The other values are
// there for the cases the default guesses wrong.
type QRStyle string

const (
	// QRAuto is QRBlocks when the writer is a terminal and QRNone otherwise.
	// A redirected command must not write escape sequences into a log.
	QRAuto QRStyle = "auto"
	// QRBlocks draws two module rows per character cell with half blocks, and
	// sets black-on-white explicitly. The explicit colours are the point: a
	// dark terminal would otherwise draw a light-on-dark code, which is the
	// inverse of what a camera expects.
	QRBlocks QRStyle = "blocks"
	// QRASCII draws two characters per module and no escape sequences, for a
	// terminal whose block glyphs leave gaps, or for output that will be
	// printed or viewed on a light background. It is light-on-dark in a dark
	// terminal, so it is not the default.
	QRASCII QRStyle = "ascii"
	// QRNone prints no square. It is the current behaviour and stays the
	// default for anything that is not a terminal.
	QRNone QRStyle = "none"
)

// qrQuietZone is the light margin in modules. Four is the spec's minimum and
// what a camera needs to find the three finder patterns; a code with no margin
// fails to scan against a dark terminal background.
const qrQuietZone = 4

// QRQuietZone is the exported form, so a caller checking a drawing knows how
// many light modules surround the symbol.
func QRQuietZone() int { return qrQuietZone }

// ParseQRStyle reads the value of --qr. An empty value is QRAuto, and a value
// outside the list is refused rather than silently replaced: an operator who
// typed --qr ascci should be told, not handed a code they cannot scan.
func ParseQRStyle(raw string) (QRStyle, error) {
	switch s := QRStyle(strings.ToLower(strings.TrimSpace(raw))); s {
	case "":
		return QRAuto, nil
	case QRAuto, QRBlocks, QRASCII, QRNone:
		return s, nil
	default:
		return "", fmt.Errorf("--qr must be auto, blocks, ascii or none, not %q", raw)
	}
}

// EnrollURL is the page a code is entered at, with the code in the query
// string.
//
// The page reads ?code= and prefills the field, so a scan saves typing. The URL
// carries no authority: the claim still has to sign the code, and the gate
// normalises and hashes whatever it is given. It is the same secret a person
// would type, in a form a camera can carry.
//
// The path is policy.EnrollmentPrefix rather than a literal, so this cannot
// drift from the one prefix the gate serves.
func EnrollURL(origin, code string) string {
	return "https://" + origin + policy.EnrollmentPrefix + "?code=" + url.QueryEscape(code)
}

// WriteQR draws text as a QR code in the requested style.
//
// Error correction is M: a phone camera at an angle loses modules, and M costs
// nothing here — an enrollment URL and code is under 100 bytes, which is the
// same QR version at L and at M.
func WriteQR(w io.Writer, text string, style QRStyle) error {
	style = style.resolve(w)
	if style == QRNone {
		return nil
	}
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return fmt.Errorf("encode qr: %w", err)
	}
	switch style {
	case QRASCII:
		return writeQRASCII(w, code)
	default:
		return writeQRBlocks(w, code)
	}
}

// resolve turns QRAuto into the style that suits this writer. Only QRAuto is
// decided here; every other value is what the operator asked for, even when it
// is a poor fit for the terminal.
func (s QRStyle) resolve(w io.Writer) QRStyle {
	if s != QRAuto {
		return s
	}
	if isTerminal(w) {
		return QRBlocks
	}
	return QRNone
}

// isTerminal reports whether w is a character device, which is the closest a
// program can get to "a person is looking at this". A pipe or a file answers
// false, which is what keeps escape sequences out of redirected output.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// writeQRBlocks draws the code with two module rows in one character cell:
// upper half, lower half, full block, or neither. One escape sequence sets the
// whole square to black on white, and the reset at the end of each line means a
// terminal that does not understand the code still shows text rather than
// swallowing the rest of the output.
func writeQRBlocks(w io.Writer, c *qr.Code) error {
	const (
		darkOnLight = "\x1b[30;47m"
		reset       = "\x1b[0m"
	)
	size := c.Size + 2*qrQuietZone
	var b strings.Builder
	b.Grow(size * (size/2 + 1) * 5)
	for y := 0; y < size; y += 2 {
		b.WriteString(darkOnLight)
		for x := 0; x < size; x++ {
			top, bottom := qrDark(c, x, y), qrDark(c, x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteByte(' ')
			}
		}
		b.WriteString(reset)
		b.WriteByte('\n')
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// writeQRASCII draws one module as two characters, so the square stays square
// in a cell that is twice as tall as it is wide. Two characters per module also
// makes it legible in a terminal whose block glyphs are not joined.
func writeQRASCII(w io.Writer, c *qr.Code) error {
	size := c.Size + 2*qrQuietZone
	var b strings.Builder
	b.Grow(size * size * 2)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if qrDark(c, x, y) {
				b.WriteString("██")
			} else {
				b.WriteString("  ")
			}
		}
		b.WriteByte('\n')
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// qrDark reports whether the module at (x, y) is dark, counting the quiet zone.
// Anything outside the symbol is light, which is what draws the margin.
func qrDark(c *qr.Code, x, y int) bool {
	x -= qrQuietZone
	y -= qrQuietZone
	if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
		return false
	}
	return c.Black(x, y)
}
