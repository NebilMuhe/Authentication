package symmetric

import (
	"log"
	"time"

	"github.com/aead/chacha20poly1305"
	"github.com/o1egl/paseto"
)

type Paseto struct {
	SecretKey           []byte
	Isuuer              string
	TokenExpirationTime time.Time
}

type PasteoResponse struct {
	Token     string
	ExpiresAt time.Time
}

type PasetoService interface {
	CreateToken(id, footer, audience string, notBeforeTime time.Time) (*PasteoResponse, error)
	VerifyToken(token string) (bool, error)
}

func NewSymmetricPasteo(paseto Paseto) PasetoService {
	// Validate the secret key length
	if len(paseto.SecretKey) != chacha20poly1305.KeySize {
		log.Panicf("Invalid secret key length: %d. It should be %v bytes.",
			len(paseto.SecretKey), chacha20poly1305.KeySize)
	}
	return &Paseto{
		SecretKey:           paseto.SecretKey,
		Isuuer:              paseto.Isuuer,
		TokenExpirationTime: paseto.TokenExpirationTime,
	}
}

func (p *Paseto) CreateToken(id, footer, audience string, notBeforeTime time.Time) (*PasteoResponse, error) {
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
		return nil, err
	}

	return &PasteoResponse{
		Token:     token,
		ExpiresAt: p.TokenExpirationTime,
	}, nil

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
