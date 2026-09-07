//go:build tools

// Package tools pins the build-time tooling. The build tag keeps it out of
// every ordinary build; it exists so `go mod tidy` retains the imports.
package tools

import _ "github.com/sqlc-dev/sqlc/cmd/sqlc"
