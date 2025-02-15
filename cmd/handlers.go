package main

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
	"github.com/kacperhemperek/go-auth-chi/internal/auth"
	"github.com/kacperhemperek/go-auth-chi/internal/mailer"
	"github.com/kacperhemperek/go-auth-chi/internal/store"
)

func registerHandler(s *store.Storage, m mailer.Mailer) http.HandlerFunc {
	type registerRequest struct {
		Email           string `json:"email" validate:"required,min=3,max=255,email"`
		Password        string `json:"password" validate:"required,min=8,max=30"`
		ConfirmPassword string `json:"confirmPassword" validate:"required,min=8,max=30,eqfield=Password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		sessCookie, err := r.Cookie("session")
		if err == nil {
			_, err := s.Session.Validate(r.Context(), sessCookie.Value)
			if err == nil {
				writeJSONError(w, http.StatusBadRequest, "User already logged in")
				return
			}
		}
		req := &registerRequest{}
		if err := readAndValidateJSON(w, r, req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		newUser := &store.User{
			Email: req.Email,
		}
		if err := newUser.Password.Set(req.Password); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		tx, err := s.Transaction.Begin()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer func(tx *sqlx.Tx) {
			if err != nil {
				s.Transaction.Rollback(tx)
			}
		}(tx)

		err = s.User.Create(r.Context(), newUser, tx)
		if err != nil && err != store.ErrDuplicateEmail {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err != nil && err == store.ErrDuplicateEmail {
			writeJSONError(w, http.StatusBadRequest, "Email already taken")
			return
		}
		user, err := s.User.GetByEmail(r.Context(), req.Email)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		token, err := s.Session.Create(
			r.Context(),
			&store.Session{
				UserID:    user.ID,
				IPAddress: r.RemoteAddr,
				UserAgent: r.UserAgent(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			tx,
		)

		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		validationToken, err := s.Token.Create(
			r.Context(),
			&store.Token{
				UserID: user.ID,
			},
			tx,
		)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		err = s.Transaction.Commit(tx)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		err = m.SendVerificationEmail(user.Email, validationToken)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
		}
		cookie := auth.NewSessionCookie(token)
		http.SetCookie(w, cookie)

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "User registered successfully"})
	}

}

func loginHandler(s *store.Storage) http.HandlerFunc {
	type loginRequest struct {
		Email    string `json:"email" validate:"required"`
		Password string `json:"password" validate:"required"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		sessCookie, err := r.Cookie("session")
		if err == nil {
			_, err := s.Session.Validate(r.Context(), sessCookie.Value)
			if err == nil {
				writeJSONError(w, http.StatusBadRequest, "User already logged in")
				return
			}
		}

		req := &loginRequest{}
		if err := readAndValidateJSON(w, r, req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		user, err := s.User.GetByEmail(r.Context(), req.Email)
		if err != nil && err != store.ErrNotFound {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err != nil && err == store.ErrNotFound {
			writeJSONError(w, http.StatusUnauthorized, "Invalid email or password")
			return
		}

		if !user.Password.Compare(req.Password) {
			writeJSONError(w, http.StatusUnauthorized, "Invalid email or password")
			return
		}

		token, err := s.Session.Create(
			r.Context(),
			&store.Session{
				UserID:    user.ID,
				IPAddress: r.RemoteAddr,
				UserAgent: r.UserAgent(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			nil,
		)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		cookie := auth.NewSessionCookie(token)
		http.SetCookie(w, cookie)

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "User logged in successfully"})
	}
}

func getMeHandler(s *store.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromContext(r)
		writeJSONResponse(w, http.StatusOK, map[string]any{"user": user})
	}
}

func logoutHandler(s *store.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		cookie := auth.DeleteSessionCookie()
		http.SetCookie(w, cookie)

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "User logged out successfully"})
		return
	}
}

func verifyEmail(s *store.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := chi.URLParam(r, "token")

		if tokenStr == "" {
			writeJSONError(w, http.StatusBadRequest, "Token is required")
			return
		}

		token, err := s.Token.Validate(r.Context(), tokenStr)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid token")
			return
		}
		user, err := s.User.GetByID(r.Context(), token.UserID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		user.EmailVerified = true
		_, err = s.User.Update(r.Context(), user, nil)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		err = s.Token.Delete(r.Context(), token.Token, nil)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Email verified successfully"})
		return
	}
}
