package console

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"rsc.io/qr"
)

// The QR path is display-only, so its tests are about two properties: the
// square is a faithful drawing of the payload, and nothing about it changes the
// text an existing operator script already parses.

func TestParseQRStyle(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    QRStyle
		wantErr bool
	}{
		{in: "", want: QRAuto},
		{in: "auto", want: QRAuto},
		{in: "blocks", want: QRBlocks},
		{in: "ASCII", want: QRASCII},
		{in: " none ", want: QRNone},
		{in: "ascci", wantErr: true},
		{in: "svg", wantErr: true},
	} {
		got, err := ParseQRStyle(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseQRStyle(%q) accepted a bad value as %q", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseQRStyle(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseQRStyle(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestEnrollURLIsThePageWithTheCode pins the payload the phone scans. It is the
// gate's own prefix and the page's documented ?code= prefill, so a change here
// is a change to the contract the mobile app follows.
func TestEnrollURLIsThePageWithTheCode(t *testing.T) {
	got := EnrollURL("aivan-hud.home.arpa", "Q3N2-QA2B-P4BB-FAN9-DTW1-RRXD-2M")
	want := "https://aivan-hud.home.arpa/__aivan/enroll?code=Q3N2-QA2B-P4BB-FAN9-DTW1-RRXD-2M"
	if got != want {
		t.Fatalf("EnrollURL = %q, want %q", got, want)
	}
}

// TestEnrollURLEscapesTheCode: the code alphabet has no character that needs
// escaping today, so this pins the escaping for the day a display form adds one
// rather than letting a raw '&' split the query.
func TestEnrollURLEscapesTheCode(t *testing.T) {
	got := EnrollURL("aivan-hud.home.arpa", "AB&CD")
	if !strings.HasSuffix(got, "?code=AB%26CD") {
		t.Fatalf("EnrollURL did not escape the code: %q", got)
	}
}

// TestWriteQRStyleNoneWritesNothing is what keeps redirected output clean: the
// none style must add no bytes at all, not even a newline.
func TestWriteQRStyleNoneWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteQR(&buf, "anything", QRNone); err != nil {
		t.Fatalf("WriteQR: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("QRNone wrote %q", buf.String())
	}
}

// TestQRAutoWritesNoSquareToAPipe: auto must decide by the writer. A buffer is
// not a terminal, so the default adds nothing and a script's output is
// unchanged.
func TestQRAutoWritesNoSquareToAPipe(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteQR(&buf, "anything", QRAuto); err != nil {
		t.Fatalf("WriteQR: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("QRAuto wrote %d bytes to a non-terminal", buf.Len())
	}
}

// TestQRASCIIIsAFaithfulDrawing turns the drawn characters back into a module
// grid and compares it with the encoder's own bitmap. It catches the two ways a
// renderer breaks a code: a missing quiet zone, and rows or columns shifted by
// one.
func TestQRASCIIIsAFaithfulDrawing(t *testing.T) {
	const payload = "https://aivan-hud.home.arpa/__aivan/enroll?code=Q3N2-QA2B-P4BB-FAN9-DTW1-RRXD-2M"

	want, err := qr.Encode(payload, qr.M)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteQR(&buf, payload, QRASCII); err != nil {
		t.Fatalf("WriteQR: %v", err)
	}

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	// Four is the spec's minimum quiet zone, pinned here as a literal so this
	// fails if the constant is changed rather than following it.
	size := want.Size + 2*4
	if len(lines) != size {
		t.Fatalf("drew %d rows, want %d (symbol %d + quiet zone)", len(lines), size, want.Size)
	}

	for y, line := range lines {
		// One module is two runes; █ is three bytes in UTF-8, so the width is
		// counted in runes rather than bytes.
		runes := []rune(line)
		if len(runes) != size*2 {
			t.Fatalf("row %d is %d runes, want %d", y, len(runes), size*2)
		}
		for x := 0; x < size; x++ {
			drawn := string(runes[x*2:x*2+2]) == "██"
			wantDark := false
			mx, my := x-4, y-4
			if mx >= 0 && my >= 0 && mx < want.Size && my < want.Size {
				wantDark = want.Black(mx, my)
			}
			if drawn != wantDark {
				t.Fatalf("module (%d,%d): drawn dark=%v, encoder dark=%v", x, y, drawn, wantDark)
			}
		}
	}
}

// TestQRBlocksDrawsHalfRowsAndForcesColours: the block style must draw two
// module rows per line, and must set black-on-white explicitly. A terminal's
// default colours would otherwise invert the square and a camera would refuse
// it.
func TestQRBlocksDrawsHalfRowsAndForcesColours(t *testing.T) {
	const payload = "https://aivan-hud.home.arpa/__aivan/enroll?code=Q3N2-QA2B-P4BB-FAN9-DTW1-RRXD-2M"

	want, err := qr.Encode(payload, qr.M)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteQR(&buf, payload, QRBlocks); err != nil {
		t.Fatalf("WriteQR: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "\x1b[30;47m") {
		t.Error("the square does not set black-on-white, so a dark terminal would invert it")
	}
	if n := strings.Count(out, "\x1b[0m"); n != len(strings.Split(strings.TrimSuffix(out, "\n"), "\n")) {
		t.Errorf("reset count %d does not match the line count; a missing reset bleeds colour", n)
	}

	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	size := want.Size + 2*4
	// Two module rows per line, rounded up: an odd row count ends on a
	// half-filled cell.
	if got, wantLines := len(lines), (size+1)/2; got != wantLines {
		t.Fatalf("drew %d lines, want %d for %d module rows", got, wantLines, size)
	}
}

// TestWriteEnrollQRLeavesTheTextAlone is the compatibility guarantee: with the
// default style on a pipe, the output is byte-identical to WriteEnroll, and the
// code still appears exactly once as text.
func TestWriteEnrollQRLeavesTheTextAlone(t *testing.T) {
	r := EnrollResult{
		RecordID: "9a82a19a-7e53-41d9-8a8f-2a3c0d833be5",
		UserID:   10,
		Username: "chris",
		Origin:   "aivan-hud.home.arpa",
		Kind:     "phone",
		Code:     "Q3N2-QA2B-P4BB-FAN9-DTW1-RRXD-2M",
		Expires:  time.Now().Add(15 * time.Minute),
	}

	var plain, auto bytes.Buffer
	if err := WriteEnroll(&plain, r); err != nil {
		t.Fatalf("WriteEnroll: %v", err)
	}
	if err := WriteEnrollQR(&auto, r, QRAuto); err != nil {
		t.Fatalf("WriteEnrollQR: %v", err)
	}
	if plain.String() != auto.String() {
		t.Fatalf("auto style changed the text:\n--- WriteEnroll ---\n%s\n--- WriteEnrollQR ---\n%s",
			plain.String(), auto.String())
	}
	if n := strings.Count(plain.String(), r.Code); n != 1 {
		t.Fatalf("the code appears %d times in the text, want once", n)
	}

	// With a square, the text before it is unchanged and the code is still
	// printed once as characters; the square encodes the URL instead.
	var withQR bytes.Buffer
	if err := WriteEnrollQR(&withQR, r, QRASCII); err != nil {
		t.Fatalf("WriteEnrollQR: %v", err)
	}
	if n := strings.Count(withQR.String(), r.Code); n != 1 {
		t.Fatalf("the code appears %d times with a square, want once", n)
	}
	if !strings.HasPrefix(withQR.String(), plain.String()) {
		t.Fatal("the square changed the text that precedes it")
	}
}
