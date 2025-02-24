package main

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
	"github.com/kacperhemperek/go-auth-chi/internal/auth"
	"github.com/kacperhemperek/go-auth-chi/internal/mailer"
	"github.com/kacperhemperek/go-auth-chi/internal/store"
	"github.com/markbates/goth/gothic"
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

		validationToken, err := s.Verification.Create(
			r.Context(),
			store.NewVerification(
				auth.EmailVerificationIntent,
				nil,
				auth.NewNullString(user.ID),
			),
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

func getMeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromContext(r)
		writeJSONResponse(w, http.StatusOK, map[string]any{"user": user})
	}
}

func logoutHandler(s *store.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := r.Cookie("session")
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		err = s.Session.Delete(r.Context(), token.Value, nil)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

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

		token, err := s.Verification.Validate(r.Context(), tokenStr, auth.EmailVerificationIntent)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid token")
			return
		}
		if !token.UserID.Valid {
			writeJSONError(w, http.StatusInternalServerError, "Invalid token")
			return
		}
		user, err := s.User.GetByID(r.Context(), token.UserID.String)
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

		err = s.Verification.Delete(r.Context(), token.Value, nil)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Email verified successfully"})
		return
	}
}

func initPasswordReset(s *store.Storage, m mailer.Mailer) http.HandlerFunc {
	type request struct {
		Email string `json:"email" validate:"required,email"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := readAndValidateJSON(w, r, req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		user, err := s.User.GetByEmail(r.Context(), req.Email)
		if err != nil && err != store.ErrNotFound {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
		}
		if err != nil && err == store.ErrNotFound {
			writeJSONError(w, http.StatusBadRequest, "User not found")
			return
		}
		tx, err := s.Transaction.Begin()
		defer func(tx *sqlx.Tx) {
			if err != nil {
				s.Transaction.Rollback(tx)
			}
		}(tx)

		token, err := s.Verification.Create(
			r.Context(),
			store.NewVerification(
				auth.PasswordResetIntent,
				nil,
				auth.NewNullString(user.ID),
			),
			tx,
		)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to create token")
			return
		}

		if err = m.SendPasswordResetEmail(user.Email, token); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to send email")
			return
		}
		if err = s.Transaction.Commit(tx); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to commit changes")
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Password reset initiated"})
		return
	}
}

func completePasswordReset(s *store.Storage, m mailer.Mailer) http.HandlerFunc {
	type request struct {
		Password        string `json:"password" validate:"required,min=8,max=30"`
		ConfirmPassword string `json:"confirmPassword" validate:"eqfield=Password"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := chi.URLParam(r, "token")
		if tokenStr == "" {
			writeJSONError(w, http.StatusBadRequest, "Token is required")
			return
		}
		token, err := s.Verification.Validate(r.Context(), tokenStr, auth.PasswordResetIntent)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid token")
			return
		}
		if !token.UserID.Valid {
			writeJSONError(w, http.StatusInternalServerError, "Invalid token")
			return
		}
		req := &request{}
		if err := readAndValidateJSON(w, r, req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		user, err := s.User.GetByID(r.Context(), token.UserID.String)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to get user")
			return
		}

		tx, err := s.Transaction.Begin()

		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		defer func(tx *sqlx.Tx) {
			if err != nil {
				s.Transaction.Rollback(tx)
			}
		}(tx)

		user.Password.Set(req.Password)
		if _, err = s.User.Update(r.Context(), user, tx); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to update password")
			return
		}

		if err = s.Verification.Delete(r.Context(), token.Value, tx); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to delete token")
			return
		}

		if err = m.SendPasswordChangedEmail(user.Email); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to send email")
		}

		if err = s.Transaction.Commit(tx); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to commit changes")
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Password reset successfully"})
		return
	}
}

func oauthCallbackHandler(s *store.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gothUser, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, err.Error())
			return
		}

		tx, err := s.Transaction.Begin()
		user, err := s.User.GetByEmail(r.Context(), gothUser.Email)
		if err != nil {
			if err == store.ErrNotFound {
				// User does not exist, create a new one
				user = &store.User{
					Email:         gothUser.Email,
					AvatarURL:     gothUser.AvatarURL,
					AvatarSource:  "oauth",
					EmailVerified: true,
					OAuthProvider: gothUser.Provider,
					OAuthID:       gothUser.UserID,
				}
				if err = s.User.Create(r.Context(), user, tx); err != nil {
					writeJSONError(w, http.StatusInternalServerError, err.Error())
					return
				}

				user, err = s.User.GetByEmail(r.Context(), gothUser.Email)
				if err != nil {
					writeJSONError(w, http.StatusInternalServerError, err.Error())
					return
				}
			} else {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}

		// User exists, update OAuth provider and ID
		if user.OAuthProvider == "" || user.OAuthProvider != gothUser.Provider {
			user.OAuthProvider = gothUser.Provider
			user.OAuthID = gothUser.UserID
			user.EmailVerified = true
			user, err = s.User.Update(r.Context(), user, tx)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}

		// Update avatar URL if it's from OAuth provider or not set
		if user.AvatarSource == "" || user.AvatarSource == "oauth" {
			user.AvatarURL = gothUser.AvatarURL
			user.AvatarSource = "oauth"
			user, err = s.User.Update(r.Context(), user, tx)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
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
		if err = tx.Commit(); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		http.SetCookie(w, auth.NewSessionCookie(token))

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "User logged in successfully"})
	}
}

func initMagicLinkSignIn(s *store.Storage, m mailer.Mailer) http.HandlerFunc {
	type request struct {
		Email string `json:"email" validate:"required,email"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		sessionCookie, err := r.Cookie("session")
		if err == nil {
			_, err := s.Session.Validate(r.Context(), sessionCookie.Value)
			if err == nil {
				writeJSONError(w, http.StatusBadRequest, "User already logged in")
				return
			}
		}

		req := &request{}
		if err := readAndValidateJSON(w, r, req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
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

		verificationToken, err := s.Verification.Create(
			r.Context(),
			store.NewVerification(
				auth.MagicLinkIntent,
				auth.NewNullString(req.Email),
				nil,
			),
			tx,
		)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if err = m.SendMagicLinkEmail(req.Email, verificationToken); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if err = s.Transaction.Commit(tx); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "Magic link sent"})
	}
}

func completeMagicLinkSignIn(s *store.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := chi.URLParam(r, "token")

		if tokenStr == "" {
			writeJSONError(w, http.StatusBadRequest, "Token is required")
			return
		}

		verificationToken, err := s.Verification.Validate(r.Context(), tokenStr, auth.MagicLinkIntent)

		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid token")
			return
		}

		// Email is required for magic link sign in to make sure we can create a user if it doesn't exist and find user by email if it does
		if !verificationToken.Email.Valid {
			writeJSONError(w, http.StatusBadRequest, "Invalid token")
		}

		user, err := s.User.GetByEmail(r.Context(), verificationToken.Email.String)

		tx, err := s.Transaction.Begin()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
		}

		defer func(tx *sqlx.Tx) {
			if err != nil {
				s.Transaction.Rollback(tx)
			}
		}(tx)

		if err != nil {
			// User does not exist, register the user with the email passed in the query string
			if err == store.ErrNotFound {
				user = &store.User{
					Email:         verificationToken.Email.String,
					EmailVerified: true,
				}
				if err = s.User.Create(r.Context(), user, tx); err != nil {
					writeJSONError(w, http.StatusInternalServerError, err.Error())
					return
				}

				user, err = s.User.GetByEmail(r.Context(), verificationToken.Email.String)
				if err != nil {
					writeJSONError(w, http.StatusInternalServerError, err.Error())
					return
				}
			} else {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}

		sessionToken, err := s.Session.Create(r.Context(), &store.Session{
			UserID:    user.ID,
			IPAddress: r.RemoteAddr,
			UserAgent: r.UserAgent(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}, tx)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		err = s.Transaction.Commit(tx)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		cookie := auth.NewSessionCookie(sessionToken)
		http.SetCookie(w, cookie)

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "User logged in successfully"})
	}
}
