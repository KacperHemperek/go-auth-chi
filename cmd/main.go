package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
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
)

type App struct {
	storage *store.Storage
	mailer  mailer.Mailer
	env     *Env
}

func (a *App) SetupGoth() {
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
}

func (a *App) GinRouter() *gin.Engine {
	a.SetupGoth()

	r := gin.Default()

	authRouter := r.Group("/auth")

	authRouter.POST("/register", gin.WrapF(registerHandler(a.storage, a.mailer)))
	authRouter.POST("/login", gin.WrapF(loginHandler(a.storage)))
	authRouter.PUT("/verify/:token", gin.WrapF(verifyEmail(a.storage)))
	authRouter.GET("/:provider", gin.WrapF(gothic.BeginAuthHandler))
	authRouter.GET("/:provider/callback", gin.WrapF(oauthCallbackHandler(a.storage)))
	authRouter.POST("/magic-link", gin.WrapF(initMagicLinkSignIn(a.storage, a.mailer)))
	authRouter.GET("/magic-link/:token", gin.WrapF(completeMagicLinkSignIn(a.storage)))
	authRouter.POST("/reset-password", gin.WrapF(initPasswordReset(a.storage, a.mailer)))
	authRouter.PUT("/reset-password/:token", gin.WrapF(completePasswordReset(a.storage, a.mailer)))

	protectedRouter := r.Group("/auth")
	protectedRouter.Use(ginMiddleware(authMiddleware(a.storage)))
	protectedRouter.GET("/me", gin.WrapF(getMeHandler()))
	protectedRouter.POST("/logout", gin.WrapF(logoutHandler(a.storage)))

	return r
}

func (a *App) Router() *chi.Mux {
	a.SetupGoth()

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
	// r := a.Router()
	r := a.GinRouter()

	port := fmt.Sprintf(":%d", a.env.Port)
	fmt.Printf("Server is running on port %s\n", port)
	s := &http.Server{
		Addr:    port,
		Handler: r,
	}
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		if err := s.ListenAndServe(); err != nil {
			log.Fatalf("Could not start server: %e", err)
		}
	}()
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}
	fmt.Println("Shutting down server...")
}

func NewApp(env *Env) (*App, error) {

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
	env, err := NewEnv()
	if err != nil {
		log.Fatalf("Could not load environment variables: %e", err)
	}
	if app, err := NewApp(env); err != nil {
		log.Fatalf("Could not start application: %e", err)
	} else {
		app.Run()
	}
}
