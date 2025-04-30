package asymmetric

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWT struct {
	// PK crypto.PrivateKey
	PrivateKey                 crypto.PrivateKey
	SigningMethod              jwt.SigningMethod
	AccessTokenExpirationTime  time.Time
	RefreshTokenExpirationTime time.Time
	Issuer                     string
}

type Token struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

type JwtService interface {
	CreateToken(id string, notBeforeTime time.Time, audience string) (*Token, error)
	VerifyToken(token string, publicKey crypto.PublicKey) (bool, error)
}

func NewAsymmetricJWT(jwt JWT) JwtService {
	return &JWT{
		PrivateKey:                 jwt.PrivateKey,
		SigningMethod:              jwt.SigningMethod,
		AccessTokenExpirationTime:  jwt.AccessTokenExpirationTime,
		RefreshTokenExpirationTime: jwt.RefreshTokenExpirationTime,
		Issuer:                     jwt.Issuer,
	}
}

func (j *JWT) CreateToken(id string, notBeforeTime time.Time, audience string) (*Token, error) {
	accessTokne := jwt.NewWithClaims(j.SigningMethod,
		jwt.RegisteredClaims{
			Subject:   id,
			Issuer:    j.Issuer,
			ExpiresAt: jwt.NewNumericDate(j.AccessTokenExpirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(notBeforeTime),
			ID:        id,
			Audience:  jwt.ClaimStrings{audience},
		})
	acToken, err := accessTokne.SignedString(j.PrivateKey)
	if err != nil {
		return nil, err
	}

	refreshToken := jwt.NewWithClaims(j.SigningMethod, jwt.RegisteredClaims{
		Subject:   id,
		Issuer:    j.Issuer,
		ExpiresAt: jwt.NewNumericDate(j.RefreshTokenExpirationTime),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(notBeforeTime),
		ID:        id,
		Audience:  jwt.ClaimStrings{audience},
	})
	rfToken, err := refreshToken.SignedString(j.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &Token{
		AccessToken:  acToken,
		RefreshToken: rfToken,
		ExpiresAt:    j.AccessTokenExpirationTime,
	}, nil
}

func (j *JWT) VerifyToken(token string, publicKey crypto.PublicKey) (bool, error) {
	tokenSlice := strings.Split(token, ".")
	if len(tokenSlice) != 3 {
		return false, fmt.Errorf("invalid token format")
	}

	sig, err := base64.RawURLEncoding.DecodeString(tokenSlice[2])
	if err != nil {
		return false, err
	}

	if err := j.SigningMethod.Verify(strings.Join(tokenSlice[:2], "."),
		sig, publicKey); err != nil {
		return false, err
	}

	return true, nil
}

