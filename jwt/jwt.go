package jwt

import "github.com/dgrijalva/jwt-go"

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type TokenClaims struct {
	jwt.StandardClaims
	UserID     int      `json:"user_id,omitempty"`
	Email      string   `json:"email,omitempty"`
	Privileges []string `json:"privileges,omitempty"`
}
