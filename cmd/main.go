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
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/gorilla/sessions"
	"github.com/gwatts/gin-adapter"
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
		provider := r.URL.Query().Get("provider")
		if provider == "" {
			return "", fmt.Errorf("provider is required")
		}
		return provider, nil
	}

	sessionStore := sessions.NewCookieStore([]byte(a.env.SessionSecret))
	gothic.Store = sessionStore

	goth.UseProviders(
		google.New(a.env.GoogleClientID, a.env.GoogleClientSecret, fmt.Sprintf("%s/auth/oauth/callback?provider=google", a.env.BaseURL), "email", "profile"),
		github.New(a.env.GithubClientID, a.env.GithubClientSecret, fmt.Sprintf("%s/auth/oauth/callback?provider=github", a.env.BaseURL), "user:email"),
	)
}

func (a *App) FiberRouter(route fiber.Router) fiber.Router {
	a.SetupGoth()

	r := route.Group("/")

	authRouter := r.Group("/auth")
	protectedRouter := r.Group("/auth")

	authRouter.Post("/register", adaptor.HTTPHandlerFunc(registerHandler(a.storage, a.mailer)))
	authRouter.Post("/login", adaptor.HTTPHandlerFunc(loginHandler(a.storage)))
	authRouter.Put("/verify/:token", adaptor.HTTPHandlerFunc(verifyEmail(a.storage)))

	// OAuth routes for authentication
	authRouter.Get("/oauth", adaptor.HTTPHandlerFunc(gothic.BeginAuthHandler))
	authRouter.Get("/oauth/callback", adaptor.HTTPHandlerFunc(oauthCallbackHandler(a.storage)))

	// Magic link routes
	authRouter.Post("/magic-link", adaptor.HTTPHandlerFunc(initMagicLinkSignIn(a.storage, a.mailer)))
	authRouter.Get("/magic-link/:token", adaptor.HTTPHandlerFunc(completeMagicLinkSignIn(a.storage)))

	// Password reset routes
	authRouter.Post("/reset-password", adaptor.HTTPHandlerFunc(initPasswordReset(a.storage, a.mailer)))
	authRouter.Put("/reset-password/:token", adaptor.HTTPHandlerFunc(completePasswordReset(a.storage, a.mailer)))

	// Protected routes
	protectedRouter.Use(adaptor.HTTPMiddleware(authMiddleware(a.storage)))
	protectedRouter.Get("/me", adaptor.HTTPHandlerFunc(getMeHandler()))
	protectedRouter.Post("/logout", adaptor.HTTPHandlerFunc(logoutHandler(a.storage)))

	return r
}

func (a *App) GinRouter() http.Handler {
	a.SetupGoth()

	r := gin.Default()

	authRouter := r.Group("/auth")

	// Email verification routes
	authRouter.POST("/register", gin.WrapF(registerHandler(a.storage, a.mailer)))
	authRouter.POST("/login", gin.WrapF(loginHandler(a.storage)))
	authRouter.PUT("/verify/:token", gin.WrapF(verifyEmail(a.storage)))

	// OAuth routes for authentication
	authRouter.GET("/oauth", gin.WrapF(gothic.BeginAuthHandler))
	authRouter.GET("/oauth/callback", gin.WrapF(oauthCallbackHandler(a.storage)))

	// Magic link routes
	authRouter.POST("/magic-link", gin.WrapF(initMagicLinkSignIn(a.storage, a.mailer)))
	authRouter.GET("/magic-link/:token", gin.WrapF(completeMagicLinkSignIn(a.storage)))

	// Password reset routes
	authRouter.POST("/reset-password", gin.WrapF(initPasswordReset(a.storage, a.mailer)))
	authRouter.PUT("/reset-password/:token", gin.WrapF(completePasswordReset(a.storage, a.mailer)))

	// Protected routes
	protectedRouter := r.Group("/auth")
	protectedRouter.Use(adapter.Wrap(authMiddleware(a.storage)))
	protectedRouter.GET("/me", gin.WrapF(getMeHandler()))
	protectedRouter.POST("/logout", gin.WrapF(logoutHandler(a.storage)))

	return r
}

func (a *App) Router() http.Handler {
	a.SetupGoth()

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Route("/auth", func(r chi.Router) {
		// Email verification routes
		r.Post("/register", registerHandler(a.storage, a.mailer))
		r.Post("/login", loginHandler(a.storage))
		r.Put("/verify/{token}", verifyEmail(a.storage))

		// OAuth routes for authentication
		r.Get("/oatuh", gothic.BeginAuthHandler)
		r.Get("/oatuh/callback", oauthCallbackHandler(a.storage))

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

func (a *App) RunFiber() {
	app := fiber.New()
	authRoute := app.Group("/")
	_ = a.FiberRouter(authRoute)
	port := fmt.Sprintf(":%d", a.env.Port)
	fmt.Printf("Server is running on port %s\n", port)
	if err := app.Listen(port); err != nil {
		log.Fatalf("Could not start server: %e", err)
	}
}

func (a *App) Run() {
	// r := a.Router()
	r := a.GinRouter()
	// r := a.FiberRouter()

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
		// app.Run()
		app.RunFiber()
	}
}
