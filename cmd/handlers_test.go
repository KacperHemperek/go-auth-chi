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
	Email         string
	EmailVerified bool
	Password      string
	SessionID     string
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
	th.app.GinRouter().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		th.t.Logf("Registration failed with status %d: %s", rr.Code, rr.Body.String())
		return nil, rr
	}

	// Set session ID to the user
	sessionCookie := th.GetSessionCookie(rr)
	if sessionCookie == nil {
		th.t.Error("No session cookie found after successful registration")
		return user, rr
	}
	assert.NotEmptyf(th.t, sessionCookie.Value, "Session cookie should not be empty after registration")
	user.SessionID = sessionCookie.Value

	return user, rr
}

func (th *TestHelper) LoginUser(email, password string) (*TestUser, *httptest.ResponseRecorder) {
	user := &TestUser{
		Email:    email,
		Password: password,
	}

	body := map[string]string{
		"email":    email,
		"password": password,
	}
	json, err := json.Marshal(body)
	assert.NoError(th.t, err)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/login",
		bytes.NewReader(json),
	)
	rr := httptest.NewRecorder()
	th.app.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		th.t.Logf("Login failed with status %d: %s", rr.Code, rr.Body.String())
		return user, rr
	}

	// Set session ID to the user
	sessionCookie := th.GetSessionCookie(rr)
	if sessionCookie == nil {
		th.t.Error("No session cookie found after successful login")
		return user, rr
	}
	user.SessionID = sessionCookie.Value

	return user, rr
}

func (th *TestHelper) LoginAs(userType TestUserType) (*TestUser, *httptest.ResponseRecorder) {
	userData, exists := TestUserData[userType]
	if !exists {
		th.t.Fatalf("Test user type %s not found", userType)
		return nil, nil
	}

	return th.LoginUser(userData.Email, userData.Password)
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
	user, rr := helper.CreateUser("new_user@example.com", "Password123!")

	dbUser, err := app.storage.User.GetByEmail(t.Context(), "new_user@example.com", nil)
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
	assert.NotNilf(t, session, "Session not found for user %s", user.Email)
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
	user, rr := helper.LoginAs(DefaultUser)
	sessionCookie := helper.GetSessionCookie(rr)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotEmpty(t, user.SessionID)
	assert.Equal(t, user.SessionID, sessionCookie.Value)
	assert.NotNil(t, sessionCookie)
	assert.NotEmpty(t, sessionCookie.Value)

	session, err := app.storage.Session.Validate(t.Context(), user.SessionID)
	assert.NoError(t, err)
	assert.NotNil(t, session)
}

func TestIntegration_LoginUserInvalidInput(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	_, rr := helper.LoginUser("test", "short")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	_, rr = helper.LoginUser("test_invalid@example.com", "WrongP@assword")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	cookies := rr.Result().Cookies()
	assert.Empty(t, cookies)
}

func TestIntegration_GetUserInfo(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	user, rr := helper.LoginAs(DefaultUser)
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
	assert.NotNil(t, sessionCookie)

	var response map[string]any
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, user.Email, response["data"].(map[string]any)["user"].(map[string]any)["email"])
}

func TestIntegration_LogoutUser(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	_, rr := helper.LoginAs(DefaultUser)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/logout",
		nil,
	)
	req.AddCookie(helper.GetSessionCookie(rr))

	rr = httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	sessionCookie := helper.GetSessionCookie(rr)
	assert.NotNil(t, sessionCookie)
	assert.Equal(t, 0, sessionCookie.MaxAge)

	// Check if the session was deleted
	session, err := app.storage.Session.Validate(t.Context(), sessionCookie.Value)
	assert.Error(t, err)
	assert.Nil(t, session)
}
