package main

import (
	"net/http"

	"github.com/kacperhemperek/go-auth-chi/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func registerHandler(s *store.Storage) http.HandlerFunc {
	type registerRequest struct {
		Email           string `json:"email" validate:"required,min=3,max=255,email"`
		Password        string `json:"password" validate:"required,min=8,max=30"`
		ConfirmPassword string `json:"confirmPassword" validate:"required,min=8,max=30,eqfield=Password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &registerRequest{}
		if err := readAndValidateJSON(w, r, req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		bytePass := []byte(req.Password)
		hash, err := bcrypt.GenerateFromPassword(bytePass, bcrypt.DefaultCost)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		err = s.User.Create(r.Context(), &store.User{
			Email:    req.Email,
			Password: hash,
		})
		if err != nil && err != store.ErrDuplicateEmail {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err != nil && err == store.ErrDuplicateEmail {
			writeJSONError(w, http.StatusBadRequest, "Email already taken")
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"message": "User registered successfully"})
	}

}

func loginHandler(s *store.Storage) http.HandlerFunc {
	type loginRequest struct {
		Email    string `json:"email" validate:"required"`
		Password string `json:"password" validate:"required"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
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

		err = bcrypt.CompareHashAndPassword(user.Password, []byte(req.Password))
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "Invalid email or password")
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{"user": user, "message": "User logged in successfully"})
	}
}

func getMeHandler(_ *store.Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := "user"
		writeJSONResponse(w, http.StatusOK, map[string]any{"user": user})
	}
}
