package token

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/AkifhanIlgaz/go-utils/config"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"time"
)

type Manager struct {
	privateKey            *rsa.PrivateKey
	publicKey             *rsa.PublicKey
	accessTokenExpiresIn  time.Duration
	refreshTokenExpiresIn time.Duration
}

type Claims struct {
	Custom map[string]any `json:"custom,omitempty"`
	jwt.RegisteredClaims
}

func NewManager(tokenConfig config.TokenConfig) (Manager, error) {
	var tokenManager Manager
	var err error

	tokenManager.privateKey, err = loadPrivateKey(tokenConfig.PrivateKeyPath)
	if err != nil {
		return tokenManager, fmt.Errorf("failed to create token manager: %w", err)
	}

	tokenManager.publicKey, err = loadPublicKey(tokenConfig.PublicKeyPath)
	if err != nil {
		return tokenManager, fmt.Errorf("failed to create token manager: %w", err)
	}

	tokenManager.accessTokenExpiresIn = time.Duration(tokenConfig.AccessTokenExpiresIn) * time.Minute
	tokenManager.refreshTokenExpiresIn = time.Duration(tokenConfig.RefreshTokenExpiresIn) * time.Hour * 24

	return tokenManager, nil
}

func (m *Manager) GenerateAccessToken(sub string, customClaims map[string]any) (string, error) {
	now := time.Now()

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessTokenExpiresIn)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			Subject:   sub,
		},
		Custom: customClaims,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signedToken, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", fmt.Errorf("error signing access token: %w", err)
	}

	return signedToken, nil
}

func (m *Manager) ParseAccessToken(accessToken string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		accessToken,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return m.publicKey, nil
		},
		// Additional validation options
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Name}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	privateKeyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read private key file: %w", err)
	}

	block, _ := pem.Decode(privateKeyBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing RSA private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	publicKeyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read public key file: %w", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(publicKeyBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Assert that the key is an RSA public key
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}

	return rsaPublicKey, nil
}
