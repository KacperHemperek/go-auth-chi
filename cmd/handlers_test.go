package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestUser struct {
	Email     string
	Password  string
	SessionID string
}

type TestHelper struct {
	t   *testing.T
	app *App
}

func newTestHelper(t *testing.T, app *App) *TestHelper {
	return &TestHelper{
		t:   t,
		app: app,
	}
}

// Logout clears any existing session since user is being signed in immediately after registration
func (th *TestHelper) Logout(rr *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/logout",
		nil,
	)
	req.AddCookie(th.GetSessionCookie(rr))

	rr = httptest.NewRecorder()
	th.app.Router().ServeHTTP(rr, req)

	return rr
}

func (th *TestHelper) GetSessionCookie(rr *httptest.ResponseRecorder) *http.Cookie {
	cookies := rr.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "session" {
			return cookie
		}
	}
	return nil
}

func (th *TestHelper) CreateUser(email, password string) (*TestUser, *httptest.ResponseRecorder) {
	user := &TestUser{
		Email:    email,
		Password: password,
	}

	body := map[string]string{
		"email":           email,
		"password":        password,
		"confirmPassword": password,
	}
	json, err := json.Marshal(body)
	assert.NoError(th.t, err)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register",
		bytes.NewReader(json),
	)
	rr := httptest.NewRecorder()
	th.app.Router().ServeHTTP(rr, req)

	// Set session ID
	if rr.Code == http.StatusCreated {
		sessionCookie := th.GetSessionCookie(rr)
		user.SessionID = sessionCookie.Value
	}

	return user, rr
}

func Test_ApplicationStarts(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	assert.NotNil(t, dbCtr)
	assert.NotNil(t, app)
}

func TestIntegration_RegisterUserSuccessful(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	user, rr := helper.CreateUser("test@example.com", "Password123!")

	dbUser, err := app.storage.User.GetByEmail(t.Context(), "test@example.com", nil)
	assert.NoError(t, err)
	assert.NotNil(t, dbUser)
	assert.Equal(t, user.Email, dbUser.Email)
	assert.True(t, dbUser.Password.Compare("Password123!"))
	assert.NotEmpty(t, dbUser.ID)

	// Check if the session cookie is set
	sessionCookie := helper.GetSessionCookie(rr)

	assert.NotNil(t, sessionCookie)
	assert.NotEmpty(t, sessionCookie.Value)

	// Validate session
	session, err := app.storage.Session.Validate(t.Context(), user.SessionID)
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, dbUser.ID, session.UserID)
}

func TestIntegration_RegisterUserInvalidInput(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	_, rr := helper.CreateUser("test", "short")

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	dbUser, err := app.storage.User.GetByEmail(t.Context(), "test", nil)
	assert.Error(t, err)
	assert.Nil(t, dbUser)

	cookies := rr.Result().Cookies()
	assert.Empty(t, cookies)
}

func TestIntegration_LoginUserSuccessful(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	_, rr := helper.CreateUser("test@example.com", "Password123!")
	helper.Logout(rr)

	// Login
	body := map[string]string{
		"email":    "test@example.com",
		"password": "Password123!",
	}
	json, err := json.Marshal(body)
	assert.NoError(t, err)
	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/login",
		bytes.NewReader(json),
	)

	rr = httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	sessionCookie := helper.GetSessionCookie(rr)
	assert.NotNil(t, sessionCookie)
	assert.NotEmpty(t, sessionCookie.Value)

	session, err := app.storage.Session.Validate(t.Context(), sessionCookie.Value)
	assert.NoError(t, err)
	assert.NotNil(t, session)

}

func Test_Integration_LoginUserInvalidInput(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	_, rr := helper.CreateUser("test@example.com", "Password123!")
	sessionCookie := helper.GetSessionCookie(rr)
	helper.Logout(rr)

	body := map[string]string{
		"email":    "test_invalid@example.com",
		"password": "AmazinglyWrongPassword123",
	}

	json, err := json.Marshal(body)
	assert.NoError(t, err)
	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/login",
		bytes.NewReader(json),
	)
	req.AddCookie(sessionCookie)

	rr = httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

}

func TestIntegration_GetUserInfo(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	user, rr := helper.CreateUser("test@example.com", "Password123!")
	sessionCookie := helper.GetSessionCookie(rr)

	req := httptest.NewRequest(
		http.MethodGet,
		"/auth/me",
		nil,
	)
	req.AddCookie(sessionCookie)

	rr = httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	response := map[string]interface{}{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, user.Email, response["data"].(map[string]interface{})["user"].(map[string]interface{})["email"])

}

func TestIntegration_LogoutUser(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	_, rr := helper.CreateUser("test@example.com", "Password123!")
	rr = helper.Logout(rr)

	assert.Equal(t, http.StatusOK, rr.Code)

	sessionCookie := helper.GetSessionCookie(rr)
	assert.NotNil(t, sessionCookie)
	assert.Equal(t, 0, sessionCookie.MaxAge)

	// Check if the session was deleted
	session, err := app.storage.Session.Validate(t.Context(), sessionCookie.Value)
	assert.Error(t, err)
	assert.Nil(t, session)
}
