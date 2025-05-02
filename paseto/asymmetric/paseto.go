package asymmetric

import (
	"time"

	"github.com/o1egl/paseto"
)

type Paseto struct {
	paseto              *paseto.V2
	PrivateKey          string
	Issuer              string
	TokenExpirationTime time.Time
}

type PasteoResponse struct {
	AccessToken string
	ExpiresAt   time.Time
}

type PasetoService interface {
	CreateToken(id string, footer string, audience string, notBeforeTime time.Time) (*PasteoResponse, error)
	VerifyToken(token string, publicKey string) (bool, error)
}

func NewAsymmetricPaseto(p Paseto) PasetoService {
	return &Paseto{
		paseto:              paseto.NewV2(),
		PrivateKey:          p.PrivateKey,
		Issuer:              p.Issuer,
		TokenExpirationTime: p.TokenExpirationTime,
	}
}

func (p *Paseto) CreateToken(id string, footer string, audience string, notBeforeTime time.Time) (*PasteoResponse, error) {
	jsonToken := paseto.JSONToken{
		Issuer:     p.Issuer,
		Subject:    id,
		Jti:        id,
		Expiration: p.TokenExpirationTime,
		IssuedAt:   time.Now(),
		NotBefore:  notBeforeTime,
		Audience:   audience,
	}

	token, err := p.paseto.Encrypt([]byte(p.PrivateKey), jsonToken, footer)
	if err != nil {
		return nil, err
	}

	return &PasteoResponse{
		AccessToken: token,
		ExpiresAt:   p.TokenExpirationTime,
	}, nil
}

func (p *Paseto) VerifyToken(token string, publicKey string) (bool, error) {
	var jsonToken paseto.JSONToken
	var footer string
	if err := p.paseto.Decrypt(token, []byte(publicKey), &jsonToken, &footer); err != nil {
		return false, err
	}

	return true, nil
}
