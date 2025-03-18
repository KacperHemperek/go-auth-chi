package main

import (
	"encoding/json"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/kacperhemperek/go-auth-chi/internal/store"
)

// JSON
var Validate *validator.Validate

type ErrEnvelope struct {
	Error string `json:"error"`
}

func NewErrEnvelope(err any) *ErrEnvelope {
	switch err := err.(type) {
	case string:
		return &ErrEnvelope{Error: err}
	case error:
		return &ErrEnvelope{Error: err.Error()}
	default:
		return &ErrEnvelope{Error: "Internal server error"}
	}
}

type DataEnvelope struct {
	Data any `json:"data"`
}

func NewDataEnvelope(data any) *DataEnvelope {
	return &DataEnvelope{Data: data}
}

func init() {
	Validate = validator.New(validator.WithRequiredStructEnabled())
}

func writeJSON(w http.ResponseWriter, status int, data any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

func readAndValidateJSON(w http.ResponseWriter, r *http.Request, data any) error {
	if err := readJSON(w, r, data); err != nil {
		return err
	}

	if err := Validate.Struct(data); err != nil {
		return err
	}

	return nil
}

func readJSON(w http.ResponseWriter, r *http.Request, data any) error {
	maxBytes := 1_048_576 // 1MB
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	return decoder.Decode(data)
}

func writeJSONError(w http.ResponseWriter, status int, message string) error {
	return writeJSON(w, status, NewErrEnvelope(message))
}

func writeJSONResponse(w http.ResponseWriter, status int, data any) error {
	type envelope struct {
		Data any `json:"data"`
	}

	return writeJSON(w, status, &envelope{Data: data})
}

// Context
type ctxKey string

const ctxUserKey = ctxKey("user")

func getUserFromContext(r *http.Request) *store.User {
	return r.Context().Value(ctxUserKey).(*store.User)
}
