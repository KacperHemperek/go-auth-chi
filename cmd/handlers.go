package main

import (
	"fmt"
	"net/http"
	"time"
)

// TODO: move to core
type UserModel struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"-"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// TODO: move to core
type CreateUserModel struct {
	Email    string
	Password string
}

// TODO: move to core
func createUser(user CreateUserModel) (*UserModel, error) {
	fmt.Println("User created")

	return &UserModel{
		ID:        1,
		Email:     user.Email,
		Password:  user.Password,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	type registerRequest struct {
		Email           string `json:"email" validate:"required,min=3,max=255,email"`
		Password        string `json:"password" validate:"required,min=8,max=30"`
		ConfirmPassword string `json:"confirmPassword" validate:"required,min=8,max=30,eqfield=Password"`
	}

	req := &registerRequest{}
	if err := readAndValidateJSON(w, r, req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	user, err := createUser(CreateUserModel{Email: req.Email, Password: req.Password})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]any{"message": "User registered successfully", "user": user})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	type loginRequest struct {
		Email    string `json:"email" validate:"required"`
		Password string `json:"password" validate:"required"`
	}

	req := &loginRequest{}
	if err := readAndValidateJSON(w, r, req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]any{"message": "User logged in successfully"})
}

func getMeHandler(w http.ResponseWriter, _ *http.Request) {
	user := &UserModel{
		ID:        1,
		Email:     "kacper@hemp.com",
		Password:  "",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	writeJSONResponse(w, http.StatusOK, map[string]any{"user": user})
}
