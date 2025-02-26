package main

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/spf13/viper"
)

// Returns url for migrations directory using file driver for migrations
func getMigrationPath() string {
	// Get the path to the migrations directory from the current file
	_, b, _, _ := runtime.Caller(0)
	migrationPath := filepath.Join(filepath.Dir(b), "migrate", "migrations")
	migrationDir := strings.Join([]string{"file://", migrationPath}, "")
	return migrationDir
}

func RunUpMigrations() error {
	// this is what application uses to connect to the database.
	dbConnStr := viper.GetString("DSN")

	db, err := sql.Open("postgres", dbConnStr)
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
	if err := m.Up(); err != nil {
		// If there are no new migrations, return the error but do not fail the process
		if !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("could not run database migrations %w", err)
		}
		fmt.Println("No migrations to apply")
	}

	m.Close()

	return nil
}

func RunDownMigrations() error {
	dbConnStr := viper.GetString("DSN")
	db, err := sql.Open("postgres", dbConnStr)
	if err != nil {
		return err
	}
	defer db.Close()
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return err
	}
	defer driver.Close()

	migrationDir := getMigrationPath()
	m, err := migrate.NewWithDatabaseInstance(migrationDir, "postgres", driver)
	if err != nil {
		return err
	}

	if err := m.Down(); err != nil {
		return err
	}

	return nil
}

// Setup is starting the application, running the migrations, inserting the test data
// into test database and returns pointer to application instance that is running
func Setup(t *testing.T) *App {
	app, err := NewApp()
	if err != nil {
		t.Fatalf("Error in application bootstrap: %v", err)
		return nil
	}
	err = RunUpMigrations()
	if err != nil {
		t.Fatalf("Error in migration up: %v", err)
		return nil
	}
	app.Run()
	return app
}
