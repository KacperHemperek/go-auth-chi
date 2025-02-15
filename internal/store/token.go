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
	DbTimestamps
}

type TokenStore struct {
	db *sqlx.DB
}

func (s *TokenStore) Create(ctx context.Context, token *Token, tx *sqlx.Tx) (string, error) {
	query := `
		INSERT INTO tokens (user_id, token, expires_at)
		VALUES (:user_id, :token, :expires_at)
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	verificationToken, err := auth.GenerateSecureToken(auth.EmailTokenBytes)
	if err != nil {
		return "", err
	}
	token.Token = verificationToken
	token.ExpiresAt = time.Now().Add(TokenDuration)

	if tx != nil {
		_, err = tx.NamedExecContext(ctx, query, token)
	} else {
		_, err = s.db.NamedExecContext(ctx, query, token)
	}
	if err != nil {
		return "", err
	}

	return verificationToken, nil
}

func (s *TokenStore) Validate(ctx context.Context, tokenStr string) (*Token, error) {
	query := `
		SELECT * FROM tokens 
    WHERE token = $1 AND expires_at > NOW()
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	token := &Token{}
	err := s.db.GetContext(ctx, token, query, tokenStr)
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			return nil, ErrNotFound
		default:
			return nil, err
		}
	}

	return token, nil
}

func (s *TokenStore) Delete(ctx context.Context, token string, tx *sqlx.Tx) error {
	query := `
		DELETE FROM tokens WHERE token = $1
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, token)
	} else {
		_, err = s.db.ExecContext(ctx, query, token)
	}
	if err != nil {
		return err
	}

	return nil
}
