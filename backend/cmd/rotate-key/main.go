// Command rotate-key re-encrypts every stored data key under a new master key.
//
// This is the operation envelope encryption exists to make cheap. Each secret
// version's data key is unwrapped with the current master key and rewrapped
// with the new one; the ciphertext itself is never read, rewritten, or even
// loaded into this process. Rotation therefore costs the same whether the
// database holds ten secrets or ten million.
//
// Usage:
//
//	VAULTLY_MASTER_KEY=<current> \
//	VAULTLY_NEW_MASTER_KEY=<new>  \
//	DATABASE_URL=postgres://...   \
//	  rotate-key [-dry-run] [-batch 500]
//
// Generate the new key with `openssl rand -base64 32`.
//
// After a successful run, VAULTLY_MASTER_KEY must be set to the new key
// everywhere the API runs. Until it is, the API cannot decrypt anything, so
// plan a restart alongside the rotation.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"

	"vaultly/backend/internal/crypto"
	"vaultly/backend/internal/db"
	"vaultly/backend/internal/db/sqlcgen"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "rotate-key: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	dryRun := flag.Bool("dry-run", false, "verify every data key can be rewrapped, then change nothing")
	batchSize := flag.Int("batch", 500, "rows to rewrap per transaction")
	flag.Parse()

	if *batchSize < 1 || *batchSize > 10_000 {
		return fmt.Errorf("-batch must be between 1 and 10000, got %d", *batchSize)
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}

	currentEncoded := os.Getenv("VAULTLY_MASTER_KEY")
	nextEncoded := os.Getenv("VAULTLY_NEW_MASTER_KEY")
	if currentEncoded == "" {
		return errors.New("VAULTLY_MASTER_KEY is required (the key currently in use)")
	}
	if nextEncoded == "" {
		return errors.New("VAULTLY_NEW_MASTER_KEY is required " +
			"(generate one with: openssl rand -base64 32)")
	}
	if currentEncoded == nextEncoded {
		// Rotating to the same key would report success while achieving
		// nothing, which is a worse outcome than refusing.
		return errors.New("the new master key is identical to the current one")
	}

	current, err := crypto.NewKeyringFromBase64(currentEncoded)
	if err != nil {
		return fmt.Errorf("VAULTLY_MASTER_KEY is invalid: %w", err)
	}
	next, err := crypto.NewKeyringFromBase64(nextEncoded)
	if err != nil {
		return fmt.Errorf("VAULTLY_NEW_MASTER_KEY is invalid: %w", err)
	}

	// Interrupting mid-run is safe because each batch commits on its own, but
	// the run should still stop at a clean boundary rather than mid-batch.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.NewPool(ctx, databaseURL, db.DefaultPoolConfig())
	if err != nil {
		return err
	}
	defer pool.Close()

	queries := sqlcgen.New(pool)

	total, err := queries.CountSecretVersions(ctx)
	if err != nil {
		return fmt.Errorf("count secret versions: %w", err)
	}
	if total == 0 {
		fmt.Println("no secret versions to rotate")
		return nil
	}

	if *dryRun {
		fmt.Printf("dry run: verifying %d secret version(s) can be rewrapped\n", total)
	} else {
		fmt.Printf("rotating %d secret version(s) in batches of %d\n", total, *batchSize)
	}

	started := time.Now()
	var processed, skipped int64
	cursor := uuid.Nil

	for {
		if err := ctx.Err(); err != nil {
			fmt.Printf("\ninterrupted after %d of %d version(s). "+
				"Rerunning with the same keys is safe: rows already on the new "+
				"key are detected and skipped.\n", processed, total)
			return err
		}

		rows, err := queries.ListSecretVersionsForRotation(ctx,
			sqlcgen.ListSecretVersionsForRotationParams{
				ID:    cursor,
				Limit: int32(*batchSize),
			})
		if err != nil {
			return fmt.Errorf("list secret versions: %w", err)
		}
		if len(rows) == 0 {
			break
		}

		// Rewrapping happens before the transaction opens, so a corrupt row is
		// found without holding a write transaction while it is discovered.
		type rewrapped struct {
			id  uuid.UUID
			dek []byte
		}
		updates := make([]rewrapped, 0, len(rows))

		for _, row := range rows {
			// Only the wrapped key matters here. The nonce and ciphertext are
			// untouched by rotation, so they are never read.
			wrapped := &crypto.Sealed{WrappedDEK: row.WrappedDek}

			sealed, err := current.Rewrap(wrapped, next)
			if err != nil {
				// A row that will not unwrap under the current key may already
				// be on the new one, left behind by an interrupted run. That
				// is the expected case on a rerun, so it is skipped rather
				// than treated as corruption. Checking makes the whole
				// rotation idempotent and therefore resumable.
				if _, already := next.Rewrap(wrapped, next); already == nil {
					skipped++
					continue
				}
				return fmt.Errorf(
					"secret version %s could not be rewrapped with either key: %w "+
						"(is VAULTLY_MASTER_KEY the key this data was written with?)",
					row.ID, err)
			}
			updates = append(updates, rewrapped{id: row.ID, dek: sealed.WrappedDEK})
		}

		cursor = rows[len(rows)-1].ID

		if !*dryRun {
			// One transaction per batch. An interrupted run leaves committed
			// batches on the new key and the rest on the old one, which the
			// skip logic above makes safe to resume.
			tx, err := pool.Begin(ctx)
			if err != nil {
				return fmt.Errorf("begin transaction: %w", err)
			}
			txQueries := queries.WithTx(tx)

			for _, update := range updates {
				if err := txQueries.UpdateSecretVersionWrappedDEK(ctx,
					sqlcgen.UpdateSecretVersionWrappedDEKParams{
						ID:         update.id,
						WrappedDek: update.dek,
					}); err != nil {
					_ = tx.Rollback(ctx)
					return fmt.Errorf("update secret version %s: %w", update.id, err)
				}
			}

			if err := tx.Commit(ctx); err != nil {
				_ = tx.Rollback(ctx)
				return fmt.Errorf("commit batch: %w", err)
			}
		}

		processed += int64(len(rows))
		fmt.Printf("\r  %d / %d", processed, total)
	}

	fmt.Println()

	if *dryRun {
		fmt.Printf("dry run complete: %d version(s) checked, nothing was changed\n", processed)
		if skipped > 0 {
			fmt.Printf("  %d already on the new key\n", skipped)
		}
		return nil
	}

	fmt.Printf("rotated %d version(s) in %s\n",
		processed-skipped, time.Since(started).Round(time.Millisecond))
	if skipped > 0 {
		fmt.Printf("  %d already on the new key, skipped\n", skipped)
	}
	fmt.Println()
	fmt.Println("Set VAULTLY_MASTER_KEY to the new key everywhere the API runs, then restart it.")
	fmt.Println("Until you do, the API cannot decrypt any secret.")
	return nil
}
