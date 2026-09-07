// Command migrate applies or rolls back database migrations.
//
//	migrate up            apply all pending migrations
//	migrate down [n]      roll back the most recent n migrations (default 1)
//	migrate version       print the current schema version
//	migrate drop          drop every table (development only)
package main

import (
	"fmt"
	"os"
	"strconv"

	"vaultly/backend/internal/db"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}

	command := "up"
	if len(args) > 0 {
		command = args[0]
	}

	switch command {
	case "up":
		if err := db.Migrate(databaseURL); err != nil {
			return err
		}
		version, dirty, err := db.MigrationVersion(databaseURL)
		if err != nil {
			return err
		}
		fmt.Printf("schema is at version %d (dirty=%t)\n", version, dirty)
		return nil

	case "down":
		steps := 1
		if len(args) > 1 {
			n, err := strconv.Atoi(args[1])
			if err != nil || n < 1 {
				return fmt.Errorf("down expects a positive step count, got %q", args[1])
			}
			steps = n
		}
		if err := db.MigrateDown(databaseURL, steps); err != nil {
			return err
		}
		fmt.Printf("rolled back %d migration(s)\n", steps)
		return nil

	case "version":
		version, dirty, err := db.MigrationVersion(databaseURL)
		if err != nil {
			return err
		}
		fmt.Printf("version=%d dirty=%t\n", version, dirty)
		return nil

	case "drop":
		// Guarded because this is unrecoverable: it destroys every secret in
		// the database along with the schema.
		if os.Getenv("ENVIRONMENT") == "production" {
			return fmt.Errorf("refusing to drop the schema in production")
		}
		if err := db.MigrateDrop(databaseURL); err != nil {
			return err
		}
		fmt.Println("schema dropped")
		return nil

	default:
		return fmt.Errorf("unknown command %q (want up, down, version or drop)", command)
	}
}
