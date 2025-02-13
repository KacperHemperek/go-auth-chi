package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrDuplicateEmail = errors.New("duplicate email")
)

type User struct {
	ID        string    `json:"id" db:"id"`
	Email     string    `json:"email" db:"email"`
	Password  password  `json:"-" db:"password"`
	CreatedAt time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt time.Time `json:"updatedAt" db:"updated_at"`
}

type password struct {
	plain *string
	hash  []byte
}

func (p *password) Set(plainText string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainText), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	p.plain = &plainText
	p.hash = hash
	return nil
}

func (p *password) Compare(plainText string) bool {
	return bcrypt.CompareHashAndPassword(p.hash, []byte(plainText)) == nil
}

func (p *password) Scan(value any) error {
	if value == nil {
		p.hash = nil
		return nil
	}

	switch v := value.(type) {
	case []byte:
		p.hash = v
		return nil
	default:
		return errors.New("invalid password data type")
	}
}

func (p password) Value() (driver.Value, error) {
	if len(p.hash) == 0 {
		return nil, nil
	}
	return p.hash, nil
}

type UserStore struct {
	db *sqlx.DB
}

func (s *UserStore) Create(ctx context.Context, user *User) error {
	query := `
    INSERT INTO users (email, password)
    VALUES (:email, :password)
  `

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	_, err := s.db.NamedExecContext(ctx, query, user)
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
