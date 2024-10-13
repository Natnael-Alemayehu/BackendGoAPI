package password

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

type Password struct {
	PlainText *string
	Hash      []byte
}

// The Set() method calculates the bcrypt hash of a plaintext password, and stores both
// the hash and the plaintext versions in the struct.
func (p *Password) Set(plainTestPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainTestPassword), 12)
	if err != nil {
		return err
	}

	p.PlainText = &plainTestPassword
	p.Hash = hash

	return nil
}

// The Matches() method checks whether the provided plaintext password matches the
// hashed password stored in the struct, returning true if it matches and false
// otherwise.
func (p *Password) Matches(plainTestPassword string) (bool, error) {
	err := bcrypt.CompareHashAndPassword(p.Hash, []byte(plainTestPassword))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		default:
			return false, err
		}
	}
	return true, nil
}
