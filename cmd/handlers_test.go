package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ApplicationStarts(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)

	assert.NotNil(t, dbCtr)
	assert.NotNil(t, app)

	CleanupIntegration(t, dbCtr, db)
}

func TestIntegration_RegisterUserSuccessful(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)

	body := map[string]string{
		"email":           "kacper.hemperek@o2.pl",
		"password":        "AmazingPassword123",
		"confirmPassword": "AmazingPassword123",
	}

	// Convert body to io reader
	json, err := json.Marshal(body)
	assert.NoError(t, err)
	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register",
		bytes.NewReader(json),
	)
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	user, err := app.storage.User.GetByEmail(t.Context(), "kacper.hemperek@o2.pl", nil)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "kacper.hemperek@o2.pl", user.Email)
	assert.True(t, user.Password.Compare("AmazingPassword123"))
	assert.NotEmpty(t, user.ID)

	// Check if the session cookie is set and the session is valid
	sessionCookies := rr.Result().Cookies()
	fmt.Println(sessionCookies)
	var sessionCookie *http.Cookie
	for _, cookie := range sessionCookies {
		if cookie.Name == "session" {
			sessionCookie = cookie
			break
		}
	}
	assert.NotNil(t, sessionCookie)
	assert.NotEmpty(t, sessionCookie.Value)
	session, err := app.storage.Session.Validate(t.Context(), sessionCookie.Value)
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, user.ID, session.UserID)

	CleanupIntegration(t, dbCtr, db)
}

func TestIntegration_RegisterUserInvalidInput(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)

	body := map[string]string{
		"email":           "kac@per",
		"password":        "AmazingPassword123",
		"confirmPassword": "AmazingPassword123",
	}

	json, err := json.Marshal(body)
	assert.NoError(t, err)
	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register",
		bytes.NewReader(json),
	)
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	user, err := app.storage.User.GetByEmail(t.Context(), "kac@per", nil)
	assert.Error(t, err)
	assert.Nil(t, user)

	cookies := rr.Result().Cookies()
	assert.Empty(t, cookies)

	CleanupIntegration(t, dbCtr, db)
}

func TestIntegration_LoginUserSuccessful(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)

	body := map[string]string{
		"email":    "test@user1.com",
		"password": "P@ssword123_1",
	}
	json, err := json.Marshal(body)
	assert.NoError(t, err)
	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/login",
		bytes.NewReader(json),
	)
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	cookies := rr.Result().Cookies()
	assert.NotEmpty(t, cookies)
	var sessCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "session" {
			sessCookie = cookie
			break
		}
	}
	assert.NotNil(t, sessCookie)
	assert.NotEmpty(t, sessCookie.Value)
	session, err := app.storage.Session.Validate(t.Context(), sessCookie.Value)
	assert.NoError(t, err)
	assert.NotNil(t, session)

	CleanupIntegration(t, dbCtr, db)
}
