package asymmetric

import (
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestAsymmetricJWT(t *testing.T) {
	privatekey, err := os.ReadFile("./example.private.key")
	assert.NoError(t, err)
	publickey, err := os.ReadFile("./example.public.key")
	assert.NoError(t, err)

	// Parse the private key
	prKey, err := jwt.ParseRSAPrivateKeyFromPEM(privatekey)
	assert.NoError(t, err)

	pbKey, err := jwt.ParseRSAPublicKeyFromPEM(publickey)
	assert.NoError(t, err)

	jwtService := NewAsymmetricJWT(
		JWT{
			PrivateKey:                 prKey,
			SigningMethod:              jwt.SigningMethodRS256,
			AccessTokenExpirationTime:  time.Now().Add(time.Hour * 1),
			RefreshTokenExpirationTime: time.Now().Add(time.Hour * 24),
			Issuer:                     "auth",
		},
	)

	// Create a token
	token, err := jwtService.CreateToken("test-id", time.Now(), "test-audience")
	assert.NoError(t, err)

	t.Run("CreateToken", func(t *testing.T) {
		// Verify the access token is not empty
		assert.NotEmpty(t, token.AccessToken)
		// Verify the refresh token is not empty
		assert.NotEmpty(t, token.RefreshToken)
		// Verify the expiration time is approximately 1 hour from now
		expectedExpiration := time.Now().Add(time.Hour)
		if token.ExpiresAt.Before(expectedExpiration.Add(-time.Minute)) || token.ExpiresAt.After(expectedExpiration.Add(time.Minute)) {
			t.Errorf("Expected ExpiresAt to be approximately 1 hour from now, got %v", token.ExpiresAt)
		}
	})

	t.Run("Verify Token", func(t *testing.T) {
		valid, err := jwtService.VerifyToken(token.AccessToken, pbKey)
		assert.NoError(t, err)
		assert.Equal(t, true, valid)
	})
}
