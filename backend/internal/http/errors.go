// Package http contains the Gin handlers, middleware and request/response
// types. It translates between HTTP and the service layer and holds no
// business rules of its own.
package http

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"vaultly/backend/internal/domain"
	"vaultly/backend/internal/service"
)

// ErrorResponse is the single shape every failure takes, so a client only ever
// has to parse one thing.
type ErrorResponse struct {
	Error string `json:"error"`
	// Fields carries per-field problems for validation failures.
	Fields map[string]string `json:"fields,omitempty"`
	// RequestID lets a user quote a failure back and have it found in the logs.
	RequestID string `json:"requestId,omitempty"`
}

// respondError maps a domain error to a status code and writes the response.
//
// This is the only place in the codebase that decides a failure's status code.
// Handlers return errors and call this, so a new endpoint cannot invent its
// own mapping or accidentally leak an internal message.
func respondError(c *gin.Context, err error) {
	status, message, fields := classify(err)

	// Internal failures are logged in full but described vaguely, so a
	// database message never reaches a client.
	if status == http.StatusInternalServerError {
		if logger := loggerFrom(c); logger != nil {
			logger.Error("request failed", "error", err.Error())
		}
		message = "an unexpected error occurred"
	}

	c.AbortWithStatusJSON(status, ErrorResponse{
		Error:     message,
		Fields:    fields,
		RequestID: requestIDFrom(c),
	})
}

func classify(err error) (status int, message string, fields map[string]string) {
	// Validation is checked first: a ValidationError carries per-field detail
	// that the generic categories below would discard.
	var validation *domain.ValidationError
	if errors.As(err, &validation) {
		return http.StatusBadRequest, "validation failed", validation.Fields
	}

	switch {
	case errors.Is(err, domain.ErrNotFound):
		return http.StatusNotFound, "not found", nil

	case errors.Is(err, domain.ErrUnauthenticated):
		return http.StatusUnauthorized, "authentication required", nil

	case errors.Is(err, service.ErrInvalidCredentials):
		return http.StatusUnauthorized, "invalid email or password", nil

	case errors.Is(err, domain.ErrForbidden):
		return http.StatusForbidden, "you do not have permission to do that", nil

	case errors.Is(err, domain.ErrVersionMismatch):
		// 409 rather than 400: the request was well formed, but the resource
		// moved underneath it and the client can retry after refetching.
		return http.StatusConflict, "this secret has changed since you loaded it", nil

	case errors.Is(err, domain.ErrConflict):
		return http.StatusConflict, "conflicts with existing data", nil

	case errors.Is(err, domain.ErrRateLimited):
		return http.StatusTooManyRequests, "rate limit exceeded", nil

	case errors.Is(err, domain.ErrValidation):
		return http.StatusBadRequest, "validation failed", nil

	default:
		return http.StatusInternalServerError, err.Error(), nil
	}
}

// respondValidation writes a validation failure for a request that could not
// even be decoded into its expected shape.
func respondValidation(c *gin.Context, field, message string) {
	respondError(c, domain.NewValidationError(field, message))
}
