// The pages the gate serves itself, embedded into the binary.
//
// Two directories with no build step: enroll/ is the claim, login/ is the
// re-proof. Their files are served exactly as they sit in the tree. The pages
// must work on a LAN with no internet, which is why there is no CDN reference
// and no bundler in the path.
package gate

import (
	_ "embed"
)

// The files are embedded individually rather than as a filesystem so the router
// can serve a fixed set of paths and nothing else. A request for a file that is
// not in this list is a 404, not a directory listing.
var (
	//go:embed web/enroll/index.html
	enrollIndex []byte
	//go:embed web/enroll/app.js
	enrollJS []byte
	//go:embed web/enroll/canonical.js
	enrollCanonicalJS []byte

	//go:embed web/login/index.html
	loginIndex []byte
	//go:embed web/login/app.js
	loginJS []byte
	//go:embed web/login/canonical.js
	loginCanonicalJS []byte
	//go:embed web/login/reproof.js
	loginReproofJS []byte
)

// PageSource is the embedded pages. It lives in package gate rather than httpx
// so the handler that serves a page and the handler that decides for it are one
// unit.
type PageSource struct {
	Index []byte
	// JS is served at /__aivan/enroll/app.js, and Canonical at
	// /__aivan/enroll/canonical.js. Separate files so the page can be read by a
	// human, and so the canonical builder is importable by a test.
	JS        []byte
	Canonical []byte

	// The login page, served at /__aivan/login. Reproof is the module the page
	// imports, and the module an application page imports from this origin so
	// there is one implementation of the mint.
	LoginIndex     []byte
	LoginJS        []byte
	LoginCanonical []byte
	LoginReproof   []byte
}

// EmbeddedPage is the pages a shipped binary serves.
func EmbeddedPage() *PageSource {
	return &PageSource{
		Index:     enrollIndex,
		JS:        enrollJS,
		Canonical: enrollCanonicalJS,

		LoginIndex:     loginIndex,
		LoginJS:        loginJS,
		LoginCanonical: loginCanonicalJS,
		LoginReproof:   loginReproofJS,
	}
}
