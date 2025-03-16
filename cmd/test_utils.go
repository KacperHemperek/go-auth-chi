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
	"github.com/kacperhemperek/go-auth-chi/internal/auth"
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

func RunUpMigrations(db *sql.DB) error {
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

	return nil
}

func CreateTestPostgres(ctx context.Context) (*sql.DB, *pgContainer.PostgresContainer, error) {
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
		return nil, nil, fmt.Errorf("could not run postgres test container %w", err)
	}
	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return nil, nil, fmt.Errorf("could not get connection string for postgres test container %w", err)
	}

	db, err := sql.Open("postgres", connStr)

	return db, ctr, err
}

type TestUserType string

const (
	DefaultUser    TestUserType = "default"
	UnverifiedUser TestUserType = "unverified"
	NoPasswordUser TestUserType = "no_password"
)

var TestUserData = map[TestUserType]struct {
	Email         string
	Password      string
	EmailVerified bool
}{
	DefaultUser: {
		Email:         "test@example.com",
		Password:      "P@ssword123_0",
		EmailVerified: true,
	},
	UnverifiedUser: {
		Email:         "unverified@example.com",
		Password:      "P@ssword123_1",
		EmailVerified: false,
	},
	NoPasswordUser: {
		Email:         "no_password@example.com",
		Password:      "",
		EmailVerified: true,
	},
}

func PopulateDB(ctx context.Context, db *sql.DB) error {
	var defaultUserPassword auth.Hashed
	if err := defaultUserPassword.Set(TestUserData[DefaultUser].Password); err != nil {
		return fmt.Errorf("failed to hash password for user %s: %w", TestUserData[DefaultUser].Email, err)
	}

	var unverifiedUserPassword auth.Hashed
	if err := unverifiedUserPassword.Set(TestUserData[UnverifiedUser].Password); err != nil {
		return fmt.Errorf("failed to hash password for user %s: %w", TestUserData[UnverifiedUser].Email, err)
	}

	var noPasswordUserPassword auth.Hashed
	if err := noPasswordUserPassword.Set(TestUserData[NoPasswordUser].Password); err != nil {
		return fmt.Errorf("failed to hash password for user %s: %w", TestUserData[NoPasswordUser].Email, err)
	}

	query := `
	INSERT INTO users (email, password, email_verified) 
	VALUES ($1, $2, $3), ($4, $5, $6), ($7, $8, $9)
`

	_, err := db.ExecContext(ctx, query,
		TestUserData[DefaultUser].Email, defaultUserPassword, TestUserData[DefaultUser].EmailVerified,
		TestUserData[UnverifiedUser].Email, unverifiedUserPassword, TestUserData[UnverifiedUser].EmailVerified,
		TestUserData[NoPasswordUser].Email, noPasswordUserPassword, TestUserData[NoPasswordUser].EmailVerified,
	)
	if err != nil {
		return fmt.Errorf("could not insert test users data: %w", err)
	}

	return nil
}

// SetupIntegration is starting the application, running the migrations, inserting the test data
// into test database and returns pointer to application instance that is running
func SetupIntegration(t *testing.T) (*App, *pgContainer.PostgresContainer, *sql.DB) {
	env, err := NewEnv()
	if err != nil {
		t.Fatalf("Error in environment setup: %v", err)
		return nil, nil, nil
	}

	db, dbContainer, err := CreateTestPostgres(t.Context())
	if err != nil {
		t.Fatalf("Error in creating postgres test container: %v", err)
		return nil, nil, nil
	}
	// Set the DSN to the connection string of the database to make sure
	// the application will connect to the test database
	if env.DSN, err = dbContainer.ConnectionString(t.Context(), "sslmode=disable"); err != nil {
		t.Fatalf("Error in getting connection string for the database: %v", err)
		return nil, nil, nil
	}

	app, err := NewApp(env)
	if err != nil {
		t.Fatalf("Error in application bootstrap: %v", err)
		return nil, nil, nil
	}
	err = RunUpMigrations(db)
	if err != nil {
		t.Fatalf("Error in migration up: %v", err)
		return nil, nil, nil
	}
	err = PopulateDB(t.Context(), db)
	if err != nil {
		t.Fatalf("Error in populating test database: %v", err)
		return nil, nil, nil
	}
	// Run the application in the background to not block main test execution
	return app, dbContainer, db
}

func CleanupIntegration(t *testing.T, ctr *pgContainer.PostgresContainer, db *sql.DB) {
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Error in closing database connection: %v", err)
			return
		}
		if err := testcontainers.TerminateContainer(ctr); err != nil {
			t.Fatalf("Error in terminating postgres test container: %v", err)
			return
		}
	})
}
