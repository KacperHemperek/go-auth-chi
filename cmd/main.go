package main

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Post("/auth/register", registerHandler)
	r.Post("/auth/login", loginHandler)
	r.Get("/auth/me", getMeHandler)
	fmt.Println("Server is running on port 2137")
	http.ListenAndServe(":2137", r)
}
