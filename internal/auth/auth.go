package auth

import (
	"crypto/rand"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
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

type VerificationIntent int

const (
	PasswordReset VerificationIntent = iota
	EmailVerification
	OneTimePassword
	MagicLink
)

var verificationIntentToString = map[VerificationIntent]string{
	PasswordReset:     "password_reset",
	EmailVerification: "email_verification",
	OneTimePassword:   "one_time_password",
	MagicLink:         "magic_link",
}

var stringToVerificationIntent = map[string]VerificationIntent{
	"password_reset":     PasswordReset,
	"email_verification": EmailVerification,
	"one_time_password":  OneTimePassword,
	"magic_link":         MagicLink,
}

func (v VerificationIntent) String() string {
	if str, ok := verificationIntentToString[v]; ok {
		return str
	}
	return "unknown"
}

func (v VerificationIntent) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

func (v *VerificationIntent) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	intent, ok := stringToVerificationIntent[str]
	if !ok {
		return errors.New("invalid VerificationIntent value")
	}

	*v = intent
	return nil
}

func (v VerificationIntent) Value() (driver.Value, error) {
	return int(v), nil
}

func (v *VerificationIntent) Scan(value interface{}) error {
	i, ok := value.(int64)
	if !ok {
		return errors.New("invalid VerificationIntent scan source")
	}

	*v = VerificationIntent(i)
	return nil
}

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
