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

	r.Route("/auth", func(r chi.Router) {
		r.Post("/register", registerHandler(storage, mailer))
		r.Post("/login", loginHandler(storage))
		r.Put("/verify/{token}", verifyEmail(storage))

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware(storage))
			r.Get("/me", getMeHandler(storage))
			r.Post("/logout", logoutHandler(storage))
		})
	})

	fmt.Println("Server is running on port 2137")
	http.ListenAndServe(":2137", r)
}
