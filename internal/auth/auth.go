package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	SessionDuration         = 7 * 24 * time.Hour
	SessionRefreshThreshold = SessionDuration / 2
)

const (
	SessionTokenBytes = 32
	EmailTokenBytes   = 64
)

type Hashed []byte

func (p *Hashed) Set(plainText string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainText), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	*p = hash
	return nil
}

func (p *Hashed) Compare(plainText string) bool {
	return bcrypt.CompareHashAndPassword(*p, []byte(plainText)) == nil
}

func GenerateSecureToken(n int) (string, error) {
	if n <= 0 {
		return "", errors.New("token length must be greater than 0")
	}

	token := make([]byte, n)
	_, err := rand.Read(token)
	if err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}

	return base64.URLEncoding.EncodeToString(token), nil
}

func baseCookie(token string, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{
		HttpOnly: true,
		// TODO: Set to true when running in the production environment and using HTTPS
		Secure:  false,
		Value:   token,
		Expires: expiresAt,
		Name:    "session",
		Path:    "/",
	}
}

func NewSessionCookie(token string) *http.Cookie {
	return baseCookie(token, time.Now().Add(SessionDuration))
}

func DeleteSessionCookie() *http.Cookie {
	return baseCookie("", time.Now().Add(-time.Hour))
}
