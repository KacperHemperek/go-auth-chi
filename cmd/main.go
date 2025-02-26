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
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
	"github.com/spf13/viper"
)

type env struct {
	BaseURL            string
	Port               int
	SessionSecret      string
	DSN                string
	GoogleClientSecret string
	GoogleClientID     string
	GithubClientSecret string
	GithubClientID     string
}

func NewEnv() (*env, error) {
	viper.SetConfigFile(".env")
	viper.SetDefault("BASE_URL", "http://localhost:8080")
	viper.SetDefault("PORT", "8080")
	viper.SetDefault("SESSION_SECRET", "change-me")
	viper.SetDefault("DSN", "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	return &env{
		BaseURL:            viper.GetString("BASE_URL"),
		Port:               viper.GetInt("PORT"),
		SessionSecret:      viper.GetString("SESSION_SECRET"),
		DSN:                viper.GetString("DSN"),
		GoogleClientSecret: viper.GetString("GOOGLE_CLIENT_SECRET"),
		GoogleClientID:     viper.GetString("GOOGLE_CLIENT_ID"),
		GithubClientSecret: viper.GetString("GITHUB_CLIENT_SECRET"),
		GithubClientID:     viper.GetString("GITHUB_CLIENT_ID"),
	}, nil
}

type App struct {
	storage *store.Storage
	mailer  mailer.Mailer
	env     *env
}

func (a *App) Router() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Route("/auth", func(r chi.Router) {
		// Email verification routes
		r.Post("/register", registerHandler(a.storage, a.mailer))
		r.Post("/login", loginHandler(a.storage))
		r.Put("/verify/{token}", verifyEmail(a.storage))

		// OAuth routes for authentication
		r.Get("/{provider}", gothic.BeginAuthHandler)
		r.Get("/{provider}/callback", oauthCallbackHandler(a.storage))

		// Magic link routes
		r.Post("/magic-link", initMagicLinkSignIn(a.storage, a.mailer))
		r.Get("/magic-link/{token}", completeMagicLinkSignIn(a.storage))

		// Password reset routes
		r.Post("/reset-password", initPasswordReset(a.storage, a.mailer))
		r.Put("/reset-password/{token}", completePasswordReset(a.storage, a.mailer))

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware(a.storage))
			r.Get("/me", getMeHandler())
			r.Post("/logout", logoutHandler(a.storage))
		})
	})

	return r
}

func (a *App) Run() {
	gothic.GetProviderName = func(r *http.Request) (string, error) {
		provider := chi.URLParam(r, "provider")
		if provider == "" {
			return "", fmt.Errorf("provider is required")
		}
		return provider, nil
	}

	sessionStore := sessions.NewCookieStore([]byte(a.env.SessionSecret))
	gothic.Store = sessionStore

	goth.UseProviders(
		google.New(a.env.GoogleClientID, a.env.GoogleClientSecret, fmt.Sprintf("%s/auth/google/callback", a.env.BaseURL), "email", "profile"),
		github.New(a.env.GithubClientID, a.env.GithubClientSecret, fmt.Sprintf("%s/auth/github/callback", a.env.BaseURL), "user:email"),
	)
	r := a.Router()

	port := fmt.Sprintf(":%d", a.env.Port)
	fmt.Printf("Server is running on port %s\n", port)
	http.ListenAndServe(port, r)
}

func NewApp() (*App, error) {
	env, err := NewEnv()
	if err != nil {
		return nil, err
	}

	db, err := db.NewPostgres(env.DSN)
	if err != nil {
		fmt.Println("Error connecting to the database")
		fmt.Println(err)
		return nil, err
	}
	storage := store.NewStorage(db)
	mailer := mailer.New()

	return &App{
		storage: storage,
		mailer:  mailer,
		env:     env,
	}, nil
}

func main() {
	if app, err := NewApp(); err != nil {
		log.Fatalf("Could not start application: %e", err)
	} else {
		app.Run()
	}
}
