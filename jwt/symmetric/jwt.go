package symmetric

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWT struct {
	Key           []byte
	SigningMethod jwt.SigningMethod
	Token         *jwt.Token
	SignedString  string
}

type Token struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

type JwtService interface {
	CreateToken(id string) (*Token, error)
	VerifyToken(token string) bool
}

func NewSymmetricJWT(key []byte, signingMethod jwt.SigningMethod) JwtService {
	return &JWT{
		Key:           key,
		SigningMethod: signingMethod,
	}
}

func (j *JWT) CreateToken(id string) (*Token, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Subject:   id,
			Issuer:    "auth",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        id,
			Audience:  jwt.ClaimStrings{"app"},
		})
	acToken, err := accessToken.SignedString(j.Key)
	if err != nil {
		return nil, err
	}

	refreshToken := jwt.NewWithClaims(j.SigningMethod,
		jwt.RegisteredClaims{
			Subject:   id,
			Issuer:    "auth",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        id,
			Audience:  jwt.ClaimStrings{"app"},
		})
	rfToken, err := refreshToken.SignedString(j.Key)
	if err != nil {
		return nil, err
	}
	return &Token{
		AccessToken:  acToken,
		RefreshToken: rfToken,
		ExpiresAt:    time.Now().Add(time.Hour * 1),
	}, nil
}

func (j *JWT) VerifyToken(token string) bool {
	tokenSlice := strings.Split(token, ".")
	if len(tokenSlice) != 3 {
		return false
	}

	if err := j.SigningMethod.Verify(strings.Join(tokenSlice[:2], "."),
		[]byte(tokenSlice[2]), j.Key); err != nil {
		return false
	}

	return true
}
