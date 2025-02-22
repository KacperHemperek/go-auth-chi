package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/sessions"
	"github.com/kacperhemperek/go-auth-chi/internal/db"
	"github.com/kacperhemperek/go-auth-chi/internal/mailer"
	"github.com/kacperhemperek/go-auth-chi/internal/store"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
	"github.com/spf13/viper"
)

func init() {
	viper.SetConfigFile(".env")
	viper.SetDefault("BASE_URL", "http://localhost:8080")
	viper.SetDefault("PORT", "8080")
	viper.SetDefault("SESSION_SECRET", "change-me")
	viper.SetDefault("DSN", "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %v", err)
		return
	}
}

func main() {
	gothic.GetProviderName = func(r *http.Request) (string, error) {
		provider := chi.URLParam(r, "provider")
		if provider == "" {
			return "", fmt.Errorf("provider is required")
		}
		return provider, nil
	}

	sessionStore := sessions.NewCookieStore([]byte(viper.GetString("SESSION_SECRET")))
	gothic.Store = sessionStore

	goth.UseProviders(
		google.New(viper.GetString("GOOGLE_CLIENT_ID"), viper.GetString("GOOGLE_CLIENT_SECRET"), fmt.Sprintf("%s/auth/google/callback", viper.GetString("BASE_URL")), "email", "profile"),
	)

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	db, err := db.NewPostgres(viper.GetString("DSN"))
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
		r.Get("/{provider}", gothic.BeginAuthHandler)
		r.Get("/{provider}/callback", oauthCallbackHandler(storage))

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware(storage))
			r.Get("/me", getMeHandler(storage))
			r.Post("/logout", logoutHandler(storage))
		})
	})

	port := ":" + viper.GetString("PORT")
	fmt.Printf("Server is running on port %s\n", port)
	http.ListenAndServe(port, r)
}
