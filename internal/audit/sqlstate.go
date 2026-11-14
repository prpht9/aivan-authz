package audit

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// sqlState extracts PostgreSQL's SQLSTATE and the server's primary message. The
// message is the server's own short text ("relation does not exist"), not the
// client's error string, so it cannot carry a DSN.
func sqlState(err error) (state, message string, ok bool) {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return "", "", false
	}
	return pgErr.Code, pgErr.Message, true
}
