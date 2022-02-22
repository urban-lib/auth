package jwt

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/urban-lib/cbc"
	"os"
	"time"
)

var manager *auth

type AuthManager interface {
	GetTokens(userID int, email string, privileges []string) (*Tokens, error)
	GetAccessToken(userID int, email string, privileges []string) (string, error)
	GetRefreshToken() (string, error)
	ParseToken(authToken string) (*TokenClaims, error)
}

type secret32 [32]byte

func (s secret32) Set(val []byte) {
	for i, b := range val {
		s[i] = b
	}
}

func (s *secret32) Get() []byte {
	return s[:]

}

type auth struct {
	secretKey      string
	accessTTL      time.Duration
	refreshTTL     time.Duration
	superSecretKey secret32
}

func NewToken(accessTTL, refreshTTL time.Duration) error {
	secret := os.Getenv("JWTSecret")
	if secret == "" {
		return fmt.Errorf("JWTSecret on environment is empty")
	}

	superSecret := os.Getenv("JWTSuperSecret")

	if secret == "" {
		return fmt.Errorf("JWTSuperSecret on environment is empty")
	}
	if len(superSecret) < 32 {
		return fmt.Errorf("JWTSuperSecret on environment is less 32")
	} else if len(superSecret) > 32 {
		superSecret = superSecret[:32]
	}
	var super secret32
	super.Set([]byte(superSecret))
	manager = &auth{
		secretKey:      secret,
		accessTTL:      accessTTL,
		refreshTTL:     refreshTTL,
		superSecretKey: super,
	}
	return nil
}

func GetTokens(userID int, email string, privileges []string) (*Tokens, error) {
	accessToken, err := GetAccessToken(userID, email, privileges)
	if err != nil {
		return nil, fmt.Errorf("Generated error access token: %v", err)
	}

	refreshToken, err := GetRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("Generated error refresh token: %v", err)
	}
	encAccessToken, err := cbc.Encrypt([]byte(accessToken), manager.superSecretKey.Get())
	if err != nil {
		return nil, err
	}
	encRefreshToken, err := cbc.Encrypt([]byte(refreshToken), manager.superSecretKey.Get())
	if err != nil {
		return nil, err
	}
	return &Tokens{
		AccessToken:  encAccessToken,
		RefreshToken: encRefreshToken,
	}, nil
}

func GetAccessToken(userID int, email string, privileges []string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &TokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(manager.accessTTL).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		UserID:     userID,
		Email:      email,
		Privileges: privileges,
	})
	return token.SignedString([]byte(manager.secretKey))
}

func GetRefreshToken() (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &TokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(manager.accessTTL).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	})
	return token.SignedString([]byte(manager.secretKey))
}

func ParseToken(authToken string) (*TokenClaims, error) {
	decAuthToken, err := cbc.Decrypt(authToken, manager.superSecretKey.Get())
	if err != nil {
		return nil, err
	}
	token, err := jwt.ParseWithClaims(decAuthToken, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid string method")
		}
		return []byte(manager.secretKey), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		err = errors.New("Token claims error ")
		return nil, err
	}
	return claims, nil
}
