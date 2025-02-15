package store

import (
	"context"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
)

var (
	ErrNotFound = errors.New("resource not found")

	QueryTimeout = 5 * time.Second
)

type Storage struct {
	User interface {
		Create(ctx context.Context, user *User, tx *sqlx.Tx) error
		GetByID(ctx context.Context, id string) (*User, error)
		GetByEmail(ctx context.Context, email string) (*User, error)
		Update(ctx context.Context, user *User, tx *sqlx.Tx) (*User, error)
	}
	Session interface {
		Create(ctx context.Context, session *Session, tx *sqlx.Tx) (token string, err error)
		Validate(ctx context.Context, token string) (*Session, error)
		Delete(ctx context.Context, token string, tx *sqlx.Tx) error
		Refresh(ctx context.Context, oldToken string) (string, error)
	}
	Token interface {
		Create(ctx context.Context, token *Token, tx *sqlx.Tx) (string, error)
		Validate(ctx context.Context, tokenStr string) (*Token, error)
		Delete(ctx context.Context, token string, tx *sqlx.Tx) error
	}
	Transaction interface {
		Begin() (*sqlx.Tx, error)
		Commit(tx *sqlx.Tx) error
		Rollback(tx *sqlx.Tx) error
	}
}

func NewStorage(db *sqlx.DB) *Storage {
	return &Storage{
		User:        &UserStore{db: db},
		Session:     &SessionStore{db: db},
		Token:       &TokenStore{db: db},
		Transaction: &TransactionStore{db: db},
	}
}
