package auth

import (
	"crypto/rand"
	"encoding/base64"

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
