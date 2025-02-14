package main

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/kacperhemperek/go-auth-chi/internal/db"
	"github.com/kacperhemperek/go-auth-chi/internal/mailer"
	"github.com/kacperhemperek/go-auth-chi/internal/store"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	db, err := db.NewPostgres("postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable")
	if err != nil {
		fmt.Println("Error connecting to the database")
		fmt.Println(err)
		return
	}
	storage := store.NewStorage(db)
	mailer := mailer.New()

	r.Post("/auth/register", registerHandler(storage, mailer))
	r.Post("/auth/login", loginHandler(storage))
	r.Get("/auth/me", getMeHandler(storage))
	r.Post("/auth/logout", logoutHandler(storage))

	fmt.Println("Server is running on port 2137")
	http.ListenAndServe(":2137", r)
}
