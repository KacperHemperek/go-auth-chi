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
		Create(ctx context.Context, user *User) error
		GetByID(ctx context.Context, id string) (*User, error)
		GetByEmail(ctx context.Context, email string) (*User, error)
	}
	Session interface {
		Create(ctx context.Context, session *Session) (token string, err error)
		Validate(ctx context.Context, token string) (*Session, error)
		Delete(ctx context.Context, token string) error
	}
}

func NewStorage(db *sqlx.DB) *Storage {
	return &Storage{
		User:    &UserStore{db: db},
		Session: &SessionStore{db: db},
	}
}
