package db

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	pgxmigrate "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	// Registers the "pgx/v5" database/sql driver used to open the migration
	// connection. Migrations run over database/sql because that is what the
	// migration driver expects; the application itself uses pgxpool. Both go
	// through pgx, so there is only one PostgreSQL driver in the tree.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// migrator bundles a migrator with the connection it owns, so that closing it
// releases everything.
type migrator struct {
	*migrate.Migrate
	conn *sql.DB
}

// close releases the migration connection. migrate.Close returns a source and
// a database error; the database half is superseded by closing conn, and
// neither is actionable at this point.
func (m *migrator) close() {
	sourceErr, _ := m.Migrate.Close()
	_ = sourceErr
	_ = m.conn.Close()
}

func newMigrator(databaseURL string) (*migrator, error) {
	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("db: open embedded migrations: %w", err)
	}

	conn, err := sql.Open("pgx/v5", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("db: open migration connection: %w", err)
	}

	driver, err := pgxmigrate.WithInstance(conn, &pgxmigrate.Config{})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("db: create migration driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", source, "pgx5", driver)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("db: create migrator: %w", err)
	}

	return &migrator{Migrate: m, conn: conn}, nil
}

// Migrate applies every pending migration. It is safe to call on every server
// start: when the schema is already current it does nothing and returns nil.
func Migrate(databaseURL string) error {
	m, err := newMigrator(databaseURL)
	if err != nil {
		return err
	}
	defer m.close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("db: apply migrations: %w", err)
	}
	return nil
}

// MigrateDown rolls back the most recent n migrations.
func MigrateDown(databaseURL string, n int) error {
	m, err := newMigrator(databaseURL)
	if err != nil {
		return err
	}
	defer m.close()

	if err := m.Steps(-n); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("db: roll back migrations: %w", err)
	}
	return nil
}

// MigrateDrop removes every table. It exists for test fixtures and local
// resets; the server never calls it.
func MigrateDrop(databaseURL string) error {
	m, err := newMigrator(databaseURL)
	if err != nil {
		return err
	}
	defer m.close()

	if err := m.Drop(); err != nil {
		return fmt.Errorf("db: drop schema: %w", err)
	}
	return nil
}

// MigrationVersion reports the current schema version and whether the last
// migration left the database in a dirty state. A dirty schema means a
// migration failed partway and needs manual attention.
func MigrationVersion(databaseURL string) (version uint, dirty bool, err error) {
	m, err := newMigrator(databaseURL)
	if err != nil {
		return 0, false, err
	}
	defer m.close()

	version, dirty, err = m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("db: read migration version: %w", err)
	}
	return version, dirty, nil
}
