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

type Verification struct {
	ID        int                     `json:"id" db:"id"`
	Intent    auth.VerificationIntent `json:"intent" db:"intent"`
	UserID    string                  `json:"userId" db:"user_id"`
	Value     string                  `json:"value" db:"value"`
	ExpiresAt time.Time               `json:"expiresAt" db:"expires_at"`
	DbTimestamps
}

type VerificationStore struct {
	db *sqlx.DB
}

func (s *VerificationStore) Create(ctx context.Context, verification *Verification, tx *sqlx.Tx) (string, error) {
	query := `
		INSERT INTO verifications (user_id, token, expires_at, intent)
	VALUES (:user_id, :token, :expires_at, :intent)
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	verificationToken, err := auth.GenerateSecureToken(auth.EmailTokenBytes)
	if err != nil {
		return "", err
	}
	verification.Value = verificationToken
	verification.ExpiresAt = time.Now().Add(TokenDuration)

	if tx != nil {
		_, err = tx.NamedExecContext(ctx, query, verification)
	} else {
		_, err = s.db.NamedExecContext(ctx, query, verification)
	}
	if err != nil {
		return "", err
	}

	return verificationToken, nil
}

func (s *VerificationStore) Validate(ctx context.Context, tokenStr string, intent auth.VerificationIntent) (*Verification, error) {
	query := `
		SELECT * FROM verifications 
    WHERE token = $1 AND intent = $2 expires_at > NOW()
	`

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	token := &Verification{}
	err := s.db.GetContext(ctx, token, query, tokenStr, intent)
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

func (s *VerificationStore) Delete(ctx context.Context, token string, tx *sqlx.Tx) error {
	query := `
		DELETE FROM verifications WHERE token = $1
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
