// Package domain holds the types and sentinel errors shared by the service and
// transport layers. It deliberately depends on nothing else in the codebase, so
// that services can describe failures without knowing about HTTP and handlers
// can react to them without knowing about SQL.
package domain

import (
	"errors"
	"fmt"
)

// Sentinel errors. Services return these (usually wrapped with context) and the
// HTTP layer maps them to status codes in exactly one place, so no handler ever
// hand-picks a status.
var (
	// ErrNotFound means the requested resource does not exist, or the caller
	// is not permitted to know that it exists.
	ErrNotFound = errors.New("not found")

	// ErrConflict means the request collided with existing state, such as a
	// duplicate secret key within an environment.
	ErrConflict = errors.New("conflict")

	// ErrVersionMismatch means an optimistic-concurrency check failed: the
	// caller based its write on a version that is no longer current.
	ErrVersionMismatch = errors.New("version mismatch")

	// ErrUnauthenticated means no valid credential was presented.
	ErrUnauthenticated = errors.New("unauthenticated")

	// ErrForbidden means the caller is known but lacks the required role or
	// scope for this action.
	ErrForbidden = errors.New("forbidden")

	// ErrValidation means the request was structurally understood but its
	// contents are not acceptable.
	ErrValidation = errors.New("validation failed")

	// ErrRateLimited means the caller exceeded its configured request rate.
	ErrRateLimited = errors.New("rate limited")
)

// ValidationError describes one or more invalid fields. It satisfies
// errors.Is(err, ErrValidation) so callers can branch on the category while
// still surfacing per-field detail to the client.
type ValidationError struct {
	// Fields maps a request field name to a human-readable problem.
	Fields map[string]string
}

// NewValidationError builds a ValidationError for a single field.
func NewValidationError(field, message string) *ValidationError {
	return &ValidationError{Fields: map[string]string{field: message}}
}

// Add records a problem with a field, returning the receiver so that checks
// can be chained.
func (e *ValidationError) Add(field, message string) *ValidationError {
	if e.Fields == nil {
		e.Fields = make(map[string]string)
	}
	e.Fields[field] = message
	return e
}

// HasErrors reports whether any field problems were recorded.
func (e *ValidationError) HasErrors() bool { return len(e.Fields) > 0 }

// ErrorOrNil returns nil when no problems were recorded, so a validator can
// end with `return v.ErrorOrNil()` without a nil-interface trap.
func (e *ValidationError) ErrorOrNil() error {
	if e == nil || !e.HasErrors() {
		return nil
	}
	return e
}

func (e *ValidationError) Error() string {
	if len(e.Fields) == 0 {
		return "validation failed"
	}
	return fmt.Sprintf("validation failed on %d field(s)", len(e.Fields))
}

// Is makes errors.Is(err, ErrValidation) report true for a ValidationError.
func (e *ValidationError) Is(target error) bool { return target == ErrValidation }
