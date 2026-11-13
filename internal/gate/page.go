// The enrollment page, embedded into the binary.
//
// One directory with no build step: index.html, app.js and canonical.js are
// served exactly as they sit in the tree. The page must work on a LAN with no
// internet, which is why there is no CDN reference and no bundler in the path.
package gate

import (
	_ "embed"
)

// The three files are embedded individually rather than as a filesystem so the
// router can serve a fixed set of paths and nothing else. A request for a file
// that is not in this list is a 404, not a directory listing.
var (
	//go:embed web/enroll/index.html
	enrollIndex []byte
	//go:embed web/enroll/app.js
	enrollJS []byte
	//go:embed web/enroll/canonical.js
	enrollCanonicalJS []byte
)

// PageSource is the embedded page. It lives in package gate rather than httpx so
// the handler that serves it and the handler that claims it are one unit.
type PageSource struct {
	Index []byte
	// JS is served at /__aivan/enroll/app.js, and Canonical at
	// /__aivan/enroll/canonical.js. Separate files so the page can be read by a
	// human, and so the canonical builder is importable by a test.
	JS        []byte
	Canonical []byte
}

// EmbeddedPage is the page a shipped binary serves.
func EmbeddedPage() *PageSource {
	return &PageSource{
		Index:     enrollIndex,
		JS:        enrollJS,
		Canonical: enrollCanonicalJS,
	}
}
