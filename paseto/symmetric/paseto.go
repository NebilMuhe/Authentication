package symmetric

import (
	"time"

	"github.com/o1egl/paseto"
)

type Paseto struct {
	SecretKey           []byte
	Isuuer              string
	TokenExpirationTime time.Time
}

type PasetoService interface {
	CreateToken(id, footer, audience string, notBeforeTime time.Time) (string, error)
	VerifyToken(token string) (bool, error)
}

func NewSymmetricPasteo(secretKey []byte) PasetoService {
	return &Paseto{
		SecretKey: secretKey,
	}
}

func (p *Paseto) CreateToken(id, footer, audience string, notBeforeTime time.Time) (string, error) {
	v2Paseto := paseto.NewV2()

	jsonToken := paseto.JSONToken{
		Audience:   audience,
		Issuer:     p.Isuuer,
		Subject:    id,
		Jti:        id,
		Expiration: p.TokenExpirationTime,
		IssuedAt:   time.Now(),
		NotBefore:  notBeforeTime,
	}

	token, err := v2Paseto.Encrypt(p.SecretKey, jsonToken, footer)
	if err != nil {
		return "", err
	}

	return token, nil

}


func (p *Paseto) VerifyToken(token string) (bool, error) {
	v2Paseto := paseto.NewV2()

	var footer string
	jsonToken := paseto.JSONToken{}

	err := v2Paseto.Decrypt(token, p.SecretKey, &jsonToken, &footer)
	if err != nil {
		return false, err
	}

	return true, nil
}
