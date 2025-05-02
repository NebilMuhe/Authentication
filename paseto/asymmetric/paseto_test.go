package asymmetric

import (
	// "crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func TestAsymmetricPaseto(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	pasetoService := NewAsymmetricPaseto(Paseto{
		PrivateKey:          privateKey,
		Issuer:              "auth",
		TokenExpirationTime: time.Now().Add(1 * time.Hour),
	})

	response, err := pasetoService.CreateToken("test-id", "test-footer", "test-audience", time.Now())
	assert.NoError(t, err)

	t.Run("Create Token", func(t *testing.T) {
		assert.NotEmpty(t, response.AccessToken)
	})

	t.Run("Verify token", func(t *testing.T) {
		valid, err := pasetoService.VerifyToken(response.AccessToken, publicKey)
		assert.NoError(t, err)
		assert.Equal(t, true, valid)
	})
}
