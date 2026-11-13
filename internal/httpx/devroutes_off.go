//go:build !devtools

package httpx

import "net/http"

// registerDevRoutes is empty in the shipped build. The devtools build replaces
// this file, so the test-only routes are absent from the binary the cluster
// runs rather than merely unlinked.
func registerDevRoutes(*http.ServeMux) {}
