package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
	auth "github.com/kacperhemperek/go-auth-chi/internal/auth"
)

var (
	ErrDuplicateEmail = errors.New("duplicate email")
)

type User struct {
	ID            string      `json:"id" db:"id"`
	Email         string      `json:"email" db:"email"`
	Password      auth.Hashed `json:"-" db:"password"`
	EmailVerified bool        `json:"emailVerified" db:"email_verified"`
	CreatedAt     time.Time   `json:"createdAt" db:"created_at"`
	UpdatedAt     time.Time   `json:"updatedAt" db:"updated_at"`
}

type UserStore struct {
	db *sqlx.DB
}

// tx is an optional transaction in which the query will be executed.
func (s *UserStore) Create(ctx context.Context, user *User, tx *sqlx.Tx) error {
	query := `
    INSERT INTO users (email, password)
    VALUES (:email, :password)
  `

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var err error
	if tx != nil {
		_, err = s.db.NamedExecContext(ctx, query, user)

	} else {
		_, err = tx.NamedExecContext(ctx, query, user)
	}

	if err != nil {
		switch err.Error() {
		case `pq: duplicate key value violates unique constraint "users_email_key"`:
			return ErrDuplicateEmail
		default:
			return err
		}
	}

	return nil
}

func (s *UserStore) GetByID(ctx context.Context, id string) (*User, error) {
	query := `
    SELECT * FROM users
    WHERE id = $1
  `

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	user := &User{}
	err := s.db.GetContext(ctx, user, query, id)
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			return nil, ErrNotFound
		default:
			return nil, err
		}
	}

	return user, nil
}

// tx is an optional transaction in which the query will be executed.
func (s *UserStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	query := `
    SELECT * FROM users
    WHERE email = $1
  `

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	user := &User{}
	err := s.db.GetContext(ctx, user, query, email)
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			return nil, ErrNotFound
		default:
			return nil, err
		}
	}

	return user, nil
}

func (s *UserStore) Update(ctx context.Context, user *User, tx *sqlx.Tx) (*User, error) {
	query := `
	UPDATE users
	SET 
		email = :email, 
		password = :password, 
		updated_at = NOW(), 
		email_verified = :email_verified
	WHERE id = :id
	RETURNING *
  `

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	var (
		err  error
		rows *sqlx.Rows
	)
	if tx == nil {
		rows, err = s.db.NamedQueryContext(ctx, query, user)
	} else {
		query, err := tx.PrepareNamedContext(ctx, query)
		if err != nil {
			return nil, err
		}
		rows, err = query.QueryxContext(ctx, user)
	}
	if err != nil {
		return nil, err
	}

	updated := &User{}
	defer rows.Close()
	for rows.Next() {
		if err := rows.StructScan(updated); err != nil {
			return nil, err
		}
	}

	return updated, nil
}
