package symmetric

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWT struct {
	SecretKey                  []byte
	SigningMethod              jwt.SigningMethod
	AccessTokenExpirationTime  time.Time
	RefreshTokenExpirationTime time.Time
	Issuer                     string
	// Token                      *jwt.Token
	// SignedString               string
}

type Token struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

type JwtService interface {
	CreateToken(id string, notBeforeTime time.Time, audience string) (*Token, error)
	VerifyToken(token string) bool
}

func NewSymmetricJWT(jwt JWT) JwtService {
	return &JWT{
		SecretKey:                  jwt.SecretKey,
		SigningMethod:              jwt.SigningMethod,
		AccessTokenExpirationTime:  jwt.AccessTokenExpirationTime,
		RefreshTokenExpirationTime: jwt.RefreshTokenExpirationTime,
		Issuer:                     jwt.Issuer,
	}
}

func (j *JWT) CreateToken(id string, notBeforeTime time.Time, audience string) (*Token, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Subject:   id,
			Issuer:    j.Issuer,
			ExpiresAt: jwt.NewNumericDate(j.AccessTokenExpirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(notBeforeTime),
			ID:        id,
			Audience:  jwt.ClaimStrings{audience},
		})
	acToken, err := accessToken.SignedString(j.SecretKey)
	if err != nil {
		return nil, err
	}

	refreshToken := jwt.NewWithClaims(j.SigningMethod,
		jwt.RegisteredClaims{
			Subject:   id,
			Issuer:    j.Issuer,
			ExpiresAt: jwt.NewNumericDate(j.RefreshTokenExpirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(notBeforeTime),
			ID:        id,
			Audience:  jwt.ClaimStrings{audience},
		})
	rfToken, err := refreshToken.SignedString(j.SecretKey)
	if err != nil {
		return nil, err
	}
	return &Token{
		AccessToken:  acToken,
		RefreshToken: rfToken,
		ExpiresAt:    j.AccessTokenExpirationTime,
	}, nil
}

func (j *JWT) VerifyToken(token string) bool {
	tokenSlice := strings.Split(token, ".")
	if len(tokenSlice) != 3 {
		return false
	}

	fmt.Println("Token Slice:", tokenSlice)
	if err := j.SigningMethod.Verify(strings.Join(tokenSlice[:2], "."),
		[]byte(tokenSlice[2]), j.SecretKey); err != nil {
			fmt.Println("Error verifying token:", err)
		return false
	}

	return true
}
