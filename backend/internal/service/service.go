// Package service holds the business logic. It sits between the HTTP handlers
// and the database: handlers do transport concerns, this package decides what
// is allowed and what it means, and the database stores the result.
//
// Two rules hold throughout:
//
//   - Authorisation is enforced here, not only in middleware, so that every
//     path into an operation is covered.
//   - Plaintext secret values exist only inside a call, never in a stored
//     struct, and are returned only to callers permitted to see them.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"vaultly/backend/internal/crypto"
	"vaultly/backend/internal/db/sqlcgen"
	"vaultly/backend/internal/domain"
)

// Store bundles the database handles the services share.
type Store struct {
	pool    *pgxpool.Pool
	queries *sqlcgen.Queries
}

// NewStore builds a Store over a connection pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, queries: sqlcgen.New(pool)}
}

// Queries returns the query set bound to the pool.
func (s *Store) Queries() *sqlcgen.Queries { return s.queries }

// Pool returns the underlying connection pool.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// InTx runs fn inside a transaction, committing on success and rolling back on
// any error or panic. Multi-statement writes that must not be observed
// half-applied — creating a project with its environments, promoting a set of
// secrets — go through here.
func (s *Store) InTx(ctx context.Context, fn func(q *sqlcgen.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("service: begin transaction: %w", err)
	}

	// Rollback after a successful commit is a no-op, so this is safe as an
	// unconditional defer and covers the panic path too.
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(s.queries.WithTx(tx)); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("service: commit transaction: %w", err)
	}
	return nil
}

// Deps carries what every service needs.
type Deps struct {
	Store   *Store
	Keyring *crypto.Keyring
	Audit   *AuditRecorder
	Logger  *slog.Logger
}

// PostgreSQL error codes worth translating into domain errors.
const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
	pgCheckViolation      = "23514"
)

// translateDBError converts a database error into a domain error where the
// cause is unambiguous, so that a duplicate key surfaces as a conflict rather
// than a 500. Anything unrecognised is passed through wrapped.
func translateDBError(err error, what string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case pgUniqueViolation:
			return fmt.Errorf("%s: %w", what, domain.ErrConflict)
		case pgForeignKeyViolation:
			// The referenced row does not exist, which from the caller's point
			// of view means they named something that is not there.
			return fmt.Errorf("%s: %w", what, domain.ErrNotFound)
		case pgCheckViolation:
			return fmt.Errorf("%s: %w", what, domain.ErrValidation)
		}
	}

	return fmt.Errorf("%s: %w", what, err)
}

// isNoRows reports whether err is the "query returned nothing" case, which
// several call sites treat as an expected outcome rather than a failure.
func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
