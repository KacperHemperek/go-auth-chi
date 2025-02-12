MIGRATIONS_PATH = ./cmd/migrate/migrations

.PHONY: migrate-create
migration:
	@migrate create -seq -ext sql -dir $(MIGRATIONS_PATH) $(filter-out $@,$(MAKECMDGOALS))

.PHONY: migrate-up
migrate-up:
	@migrate -database postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable -path $(MIGRATIONS_PATH) up


.PHONY: migrate-down
migrate-down:
	@migrate -database postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable -path $(MIGRATIONS_PATH) down
	


