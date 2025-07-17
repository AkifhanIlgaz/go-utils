package random

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

func RandString(n int) (string, error) {
	bytes := make([]byte, n) // 256-bit (32 * 8)

	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random string: %w", err)
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

func NumericOTP(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("invalid length: %d", length)
	}

	otp := make([]byte, length)
	for i := range length {
		num, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("generate random number: %w", err)
		}
		otp[i] = byte(num.Int64() + '0')
	}

	return string(otp), nil
}

func Hash(token string) string {
	hashedBytes := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hashedBytes[:])
}
