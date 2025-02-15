package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/kacperhemperek/go-auth-chi/internal/auth"
	"github.com/kacperhemperek/go-auth-chi/internal/store"
)

func authMiddleware(s *store.Storage) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := r.Cookie("session")
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}

			session, err := s.Session.Validate(r.Context(), token.Value)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}

			// Skip session refresh for logout requests
			if !strings.HasSuffix(r.URL.Path, "/logout") {
				if time.Until(session.ExpiresAt) < auth.SessionRefreshThreshold {
					newToken, err := s.Session.Refresh(r.Context(), token.Value)
					if err != nil {
						writeJSONError(w, http.StatusInternalServerError, "failed to refresh session")
						return
					}

					http.SetCookie(w, auth.NewSessionCookie(newToken))
				}
			}

			user, err := s.User.GetByID(r.Context(), session.UserID)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}

			ctx := context.WithValue(r.Context(), ctxUserKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
