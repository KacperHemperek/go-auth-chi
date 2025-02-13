package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/kacperhemperek/go-auth-chi/internal/auth"
)

type Session struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"userId" db:"user_id"`
	Token     string    `json:"token" db:"token"`
	ExpiresAt time.Time `json:"expiresAt" db:"expires_at"`
	IPAddress string    `json:"ipAddress" db:"ip_address"`
	UserAgent string    `json:"userAgent" db:"user_agent"`
	CreatedAt time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt time.Time `json:"updatedAt" db:"updated_at"`
}

type SessionStore struct {
	db *sqlx.DB
}

func (s *SessionStore) Create(ctx context.Context, session *Session) (string, error) {
	query := `
		INSERT INTO sessions (user_id, token, expires_at, ip_address, user_agent)
		VALUES (:user_id, :token, :expires_at, :ip_address, :user_agent)
		RETURNING token
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	token := auth.GenerateToken()
	session.Token = token
	session.ExpiresAt = time.Now().Add(auth.SessionDuration)

	_, err := s.db.NamedQueryContext(ctx, query, session)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (s *SessionStore) Validate(ctx context.Context, token string) (*Session, error) {
	query := `
		SELECT * FROM sessions 
    WHERE token = $1 AND expires_at > NOW()
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	session := &Session{}
	err := s.db.GetContext(ctx, session, query, token)
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

func (s *SessionStore) Delete(ctx context.Context, token string) error {
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
