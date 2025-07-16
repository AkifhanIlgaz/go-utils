package password

import "golang.org/x/crypto/bcrypt"

type Manager interface {
	HashPassword(password string) (string, error)
	VerifyPassword(password, passwordHash string) (bool, error)
}

type BcryptPasswordManager struct {
	Cost int
}

func NewBcryptPasswordManager(cost int) BcryptPasswordManager {
	return BcryptPasswordManager{
		Cost: max(cost, bcrypt.DefaultCost),
	}
}

func (b BcryptPasswordManager) HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), b.Cost)
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

func (b BcryptPasswordManager) VerifyPassword(password, passwordHash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(password), []byte(passwordHash))
	if err != nil {
		return false, err
	}
	return true, nil
}
