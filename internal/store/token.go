package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/kacperhemperek/go-auth-chi/internal/auth"
)

var (
	TokenDuration = 5 * time.Minute
)

type Token struct {
	UserID    string    `json:"userId" db:"user_id"`
	Token     string    `json:"token" db:"token"`
	ExpiresAt time.Time `json:"expiresAt" db:"expires_at"`
	CreatedAt time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt time.Time `json:"updatedAt" db:"updated_at"`
}

type TokenStore struct {
	db *sqlx.DB
}

func (s *TokenStore) Create(ctx context.Context, token *Token) (string, error) {
	query := `
		INSERT INTO tokens (user_id, token, expires_at)
		VALUES (:user_id, :token, :expires_at)
		RETURNING token
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	verificationToken := auth.GenerateToken()
	token.Token = verificationToken
	token.ExpiresAt = time.Now().Add(TokenDuration)

	_, err := s.db.NamedQueryContext(ctx, query, token)
	if err != nil {
		return "", err
	}

	return verificationToken, nil
}

func (s *TokenStore) Validate(ctx context.Context, tokenStr, userID string) (*Token, error) {
	query := `
		SELECT * FROM tokens 
    WHERE token = $1 AND expires_at > NOW() AND user_id = $2
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	session := &Token{}
	err := s.db.GetContext(ctx, session, query, tokenStr, userID)
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			return nil, ErrNotFound
		default:
			return nil, err
		}
	}

	return session, nil
}

func (s *TokenStore) Delete(ctx context.Context, token string) error {
	query := `
		DELETE FROM sessions WHERE token = $1
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	_, err := s.db.ExecContext(ctx, query, token)
	if err != nil {
		return err
	}

	return nil
}
