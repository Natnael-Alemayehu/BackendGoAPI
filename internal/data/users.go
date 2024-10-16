package data

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	"natenine.backend.API/internal/password"
	"natenine.backend.API/internal/validator"
)

var (
	ErrDuplicateEmail = errors.New("duplicate email")
)

var AnonymousUser = &User{}

type User struct {
	ID        int64             `json:"id"`
	CreatedAt time.Time         `json:"created_at"`
	Name      string            `json:"name"`
	Email     string            `json:"email"`
	Password  password.Password `json:"-"`
	Activated bool              `json:"activated"`
	Version   int               `json:"-"`
}

// check if a user instance is AnonymousUser
func (u *User) IsAnonumous() bool {
	return u == AnonymousUser
}

func ValidateEmail(v *validator.Validator, email string) {
	v.Check(email != "", "email", "must be provided")
	v.Check(validator.Matches(email, validator.EmailRX), "email", "must be a valid email address")
}

func ValidatePassowrdPlaintext(v *validator.Validator, pass string) {
	v.Check(pass != "", "password", "must be provided")
	v.Check(len(pass) >= 8, "password", "must be at least 8 bytes long")
	v.Check(len(pass) <= 72, "password", "must not be more than 72 bytes long")
	v.Check(validator.NotIn(pass, password.CommonPasswords...), "Password", "Password is too common")
}

func ValidateUser(v *validator.Validator, user *User) {

	v.Check(user.Name != "", "name", "must be provided")
	v.Check(len(user.Name) <= 500, "name", "must not be more than 500 bytes long")

	ValidateEmail(v, user.Email)

	if user.Password.PlainText != nil {
		ValidatePassowrdPlaintext(v, *user.Password.PlainText)
	}

	// If the password hash is ever nil, this will be due to a logic error in our
	// codebase (probably because we forgot to set a password for the user).
	if user.Password.Hash == nil {
		panic("missing password hash for user")
	}
}

// Create a UserModel struct which wraps the connection pool.
type UserModel struct {
	DB *sql.DB
}

func (m UserModel) Insert(user *User) error {
	query := `
			INSERT INTO users (name, email, password_hash, activated)
			VALUES ($1, $2, $3, $4)
			RETURNING id, created_at, version`

	args := []any{user.Name, user.Email, user.Password.Hash, user.Activated}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// If the table already contains a record with this email address, then when we try
	// to perform the insert there will be a violation of the UNIQUE "users_email_key"
	err := m.DB.QueryRowContext(ctx, query, args...).Scan(&user.ID, &user.CreatedAt, &user.Version)
	if err != nil {
		switch {
		case err.Error() == `pq: duplicate key value violates unique constraint "users_email_key"`:
			return ErrDuplicateEmail
		default:
			return err
		}
	}
	return nil
}

func (m UserModel) GetByEmail(email string) (*User, error) {
	query := `
			SELECT id, created_at, name, email, password_hash, activated, version
			FROM users
			WHERE email = $1`
	var user User

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.CreatedAt,
		&user.Name,
		&user.Email,
		&user.Password.Hash,
		&user.Activated,
		&user.Version,
	)

	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}
	return &user, nil
}

func (m UserModel) Update(user *User) error {
	query := `
			UPDATE users
			SET name = $1, email= $2, password_hash=$3, activated=$4, version=version + 1
			WHERE id = $5 AND version=$6
			RETURNING version`

	args := []any{
		user.Name,
		user.Email,
		user.Password.Hash,
		user.Activated,
		user.ID,
		user.Version,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.QueryRowContext(ctx, query, args...).Scan(&user.Version)
	if err != nil {
		switch {
		case err.Error() == `pq: duplicate key value violates unique constraint "user_email_key"`:
			return ErrDuplicateEmail
		case errors.Is(err, sql.ErrNoRows):
			return ErrEditConflict
		default:
			return err
		}
	}
	return nil
}

func (m UserModel) GetForToken(tokenScope, tokenPlainText string) (*User, error) {

	// Calculate the sha256 hash of the tokenplaintext
	// This returns an ARRAY NOT A SLICE
	tokenHash := sha256.Sum256([]byte(tokenPlainText))

	query := `
			SELECT users.id, users.created_at, users.name, users.email, users.password_hash, users.activated, users.version
			FROM users
			INNER JOIN tokens
			ON users.id = tokens.user_id
			WHERE tokens.hash = $1
			AND tokens.scope = $2
			AND tokens.expiry > $3`

	// change the array into a slice using [:]
	args := []any{tokenHash[:], tokenScope, time.Now()}

	var user User

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.QueryRowContext(ctx, query, args...).Scan(
		&user.ID,
		&user.CreatedAt,
		&user.Name,
		&user.Email,
		&user.Password.Hash,
		&user.Activated,
		&user.Version,
	)

	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}

	return &user, nil
}
