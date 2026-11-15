package gate

import (
	"net/http"
)

// LoginPath is the page that re-proves a stored key.
//
// It is on the gate's own router, beside the enrollment page: the router at
// /__aivan/ goes to this service directly and never through forwardAuth, so a
// page whose job is to mint a session does not need a session to reach it. That
// is the same reason /__aivan/enroll and /__aivan/session are reached here, and
// it is why the login page needs no policy entry and no router change.
const LoginPath = "/__aivan/login"

// The login page's assets.
const (
	loginJSPath        = "/__aivan/login/app.js"
	loginCanonicalPath = "/__aivan/login/canonical.js"
	loginReproofPath   = "/__aivan/login/reproof.js"
)

// Login serves the page that mints a session from the key the browser already
// holds. It decides nothing: the page presents the key to POST
// /__aivan/session, and the gate's answer to that is the decision.
//
// A GET (or HEAD) is the page and nothing else. There is no POST here, so a
// method that is not a navigation is a 405 rather than a second write path.
func (g *Gate) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet)
		g.refuse(w, r, http.StatusMethodNotAllowed, ReasonMethodNotAllowed, forwarded{}, "login is GET")
		return
	}
	if g.page == nil || len(g.page.LoginIndex) == 0 {
		g.refuse(w, r, http.StatusNotFound, ReasonBadRequest, forwarded{}, "login page is not built")
		return
	}
	g.servePage(w, r, g.page.LoginIndex)
}

// LoginAsset serves the login page's script files, refusing every other path.
// The list is fixed, so a typo in a <script src> is a 404 rather than the page.
func (g *Gate) LoginAsset(w http.ResponseWriter, r *http.Request) {
	if g.page == nil {
		g.refuse(w, r, http.StatusNotFound, ReasonBadRequest, forwarded{}, "login assets are not built")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet)
		g.refuse(w, r, http.StatusMethodNotAllowed, ReasonMethodNotAllowed, forwarded{}, "assets are GET")
		return
	}

	var body []byte
	switch r.URL.Path {
	case loginJSPath:
		body = g.page.LoginJS
	case loginCanonicalPath:
		body = g.page.LoginCanonical
	case loginReproofPath:
		body = g.page.LoginReproof
	default:
		g.refuse(w, r, http.StatusNotFound, ReasonBadRequest, forwarded{}, "no such asset")
		return
	}
	g.serveScript(w, r, body)
}
