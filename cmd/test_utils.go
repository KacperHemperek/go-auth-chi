package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/testcontainers/testcontainers-go"
	pgContainer "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Returns url for migrations directory using file driver for migrations
func getMigrationPath() string {
	// Get the path to the migrations directory from the current file
	_, b, _, _ := runtime.Caller(0)
	migrationPath := filepath.Join(filepath.Dir(b), "migrate", "migrations")
	migrationDir := strings.Join([]string{"file://", migrationPath}, "")
	return migrationDir
}

func RunUpMigrations(connStr string) error {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("could not open database connection %w", err)
	}
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("could not initiate postgres driver for migrations %w", err)
	}

	migrationDir := getMigrationPath()
	m, err := migrate.NewWithDatabaseInstance(migrationDir, "postgres", driver)
	if err != nil {
		return fmt.Errorf("could not initiate database instance for migrations %w", err)
	}
	defer m.Close()
	if err := m.Up(); err != nil {
		// If there are no new migrations, return the error but do not fail the process
		if !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("could not run database migrations %w", err)
		}
		fmt.Println("No migrations to apply")
	}

	return nil
}

func CreatePostgresContainer(ctx context.Context) (*pgContainer.PostgresContainer, error) {
	dbUser := "postgres"
	dbPassword := "postgres"
	dbName := "postgres"

	ctr, err := pgContainer.Run(ctx, "postgres:17",
		pgContainer.WithDatabase(dbName),
		pgContainer.WithUsername(dbUser),
		pgContainer.WithPassword(dbPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("could not run postgres test container %w", err)
	}

	return ctr, nil
}

// Setup is starting the application, running the migrations, inserting the test data
// into test database and returns pointer to application instance that is running
func Setup(t *testing.T) (*App, *pgContainer.PostgresContainer) {
	env, err := NewEnv()
	if err != nil {
		t.Fatalf("Error in environment setup: %v", err)
		return nil, nil
	}

	dbContainer, err := CreatePostgresContainer(t.Context())
	if err != nil {
		t.Fatalf("Error in creating postgres test container: %v", err)
		return nil, nil
	}
	// Set the DSN to the connection string of the database to make sure
	// the application will connect to the test database
	if env.DSN, err = dbContainer.ConnectionString(t.Context(), "sslmode=disable"); err != nil {
		t.Fatalf("Error in getting connection string for the database: %v", err)
		return nil, nil
	}

	app, err := NewApp(env)
	if err != nil {
		t.Fatalf("Error in application bootstrap: %v", err)
		return nil, nil
	}
	err = RunUpMigrations(env.DSN)
	if err != nil {
		t.Fatalf("Error in migration up: %v", err)
		return nil, nil
	}
	app.Run()
	return app, dbContainer
}

func Cleanup(t *testing.T, ctr *pgContainer.PostgresContainer) {
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(ctr); err != nil {
			t.Fatalf("Error in terminating postgres test container: %v", err)
			return
		}
	})
}
