package audit

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"strings"
)

// deniedSegments are the words that make an attribute's key unacceptable. A key
// is split on "_" and "-" and denied when any segment is one of these, so
// "cookie" and "session_token" are dropped while "sessions" — a purge count —
// is kept.
//
// The list is a mechanism, not a review checklist: a careless
// slog.Info("x", "cookie", v) in future code is dropped by the handler rather
// than published.
var deniedSegments = map[string]bool{
	"cookie":        true, // cookie values, Set-Cookie
	"nonce":         true, // the single-use token
	"signature":     true, // the wire signature
	"sig":           true,
	"dsn":           true, // the database connection string
	"database_url":  true,
	"password":      true,
	"passwd":        true,
	"secret":        true,
	"token":         true, // session tokens
	"authorization": true,
	"credential":    true,
	"key":           true, // public_key and private material
	"private":       true,
}

// deniedKey reports whether key names something that must never be logged.
// Matching is case-insensitive and splits on the separators slog convention
// uses, so "X-Aivan-Signature" and "signature" are both refused. A few whole
// keys are denied as well, where their parts are individually harmless:
// database_url is a DSN even though neither half is.
func deniedKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return false
	}
	if wholeKeyDenied[key] {
		return true
	}
	fields := strings.FieldsFunc(key, func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ' '
	})
	for _, f := range fields {
		if deniedSegments[f] {
			return true
		}
	}
	return false
}

// wholeKeyDenied holds keys that are secret as a whole even though no single
// segment of them is.
var wholeKeyDenied = map[string]bool{
	"database_url":      true,
	"db_url":            true,
	"connection_string": true,
}

// Handler wraps an slog.Handler and drops every attribute whose key is denied.
// It filters at construction (WithAttrs) and at write time (Handle), and it
// recurses into groups so a secret cannot hide one level down.
type Handler struct {
	next slog.Handler
}

// NewHandler wraps next. Wrapping an already wrapped handler is harmless and
// costs one extra pass per record.
func NewHandler(next slog.Handler) *Handler { return &Handler{next: next} }

// Logger wraps logger's handler. A nil logger becomes slog.Default().
func Logger(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		logger = slog.Default()
	}
	return slog.New(NewHandler(logger.Handler()))
}

// Enabled reports the wrapped handler's decision.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

// Handle copies the record without the denied attributes and writes it.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		if kept, ok := filterAttr(a); ok {
			out.AddAttrs(kept)
		}
		return true
	})
	return h.next.Handle(ctx, out)
}

// WithAttrs filters the bound attributes before binding them.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	kept := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		if k, ok := filterAttr(a); ok {
			kept = append(kept, k)
		}
	}
	if len(kept) == 0 {
		return h
	}
	return &Handler{next: h.next.WithAttrs(kept)}
}

// WithGroup passes the group to the wrapped handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{next: h.next.WithGroup(name)}
}

func filterAttr(a slog.Attr) (slog.Attr, bool) {
	if deniedKey(a.Key) {
		return slog.Attr{}, false
	}
	if a.Value.Kind() != slog.KindGroup {
		return a, true
	}
	group := a.Value.Group()
	kept := make([]slog.Attr, 0, len(group))
	for _, ga := range group {
		if k, ok := filterAttr(ga); ok {
			kept = append(kept, k)
		}
	}
	return slog.Attr{Key: a.Key, Value: slog.GroupValue(kept...)}, true
}

// Error describes err for a log line without risking a secret. A pgx error can
// carry the connection string, so its message is never quoted: the SQLSTATE and
// the server's own short message are, and anything else is reduced to a
// classification plus a scrubbed, truncated message.
func Error(err error) string {
	if err == nil {
		return ""
	}
	if state, message, ok := sqlState(err); ok {
		return "sqlstate " + state + ": " + truncate(scrub(message), 200)
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	return truncate(scrub(err.Error()), 200)
}

// credentialValue matches a password in the shapes PostgreSQL clients print
// it: password=hunter2, password: hunter2, password 'hunter2'. The value is the
// run of non-separator characters after the keyword and an optional := or
// quote.
var credentialValue = regexp.MustCompile(`(?i)(password|passwd)([=:\s]+['"]?)([^\s'"&,;]+)`)

// urlWithCredentials matches any URL, so a connection string that reached an
// error message loses its host and user with it.
var urlWithCredentials = regexp.MustCompile(`(?i)\b(?:postgres|postgresql|https?|redis|amqp)://[^\s"'<>]+`)

// Scrub is scrub for callers outside this package, so a process writing an
// error to stderr uses the same rule as one writing it to the log.
func Scrub(s string) string { return scrub(s) }

// scrub removes anything shaped like a URL and any password value from s. It is
// a backstop for the paths that do not go through a SQLSTATE error.
func scrub(s string) string {
	s = urlWithCredentials.ReplaceAllString(s, "<url>")
	return credentialValue.ReplaceAllString(s, "$1$2<redacted>")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
