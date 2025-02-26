package main

import (
	"errors"
	"testing"

	"github.com/golang-migrate/migrate/v4"
)

func TestIntegration_Init(t *testing.T) {
	_ = Setup(t)

	t.Cleanup(func() {
		if err := RunDownMigrations(); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				return
			}
			t.Errorf("Error in cleanup: %v", err)
		}

	})
}
