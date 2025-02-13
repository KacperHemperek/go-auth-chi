package auth

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
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

func GenerateToken() string {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(token)
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
	return baseCookie(token, time.Now().Add(24*time.Hour))
}

func DeleteSessionCookie() *http.Cookie {
	return baseCookie("", time.Now().Add(-time.Hour))
}
