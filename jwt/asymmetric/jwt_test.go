package asymmetric

import (
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestAsymmetricJWT(t *testing.T) {
	privatekey, err := os.ReadFile("./example.private.key")
	require.NoError(t, err)
	publickey, err := os.ReadFile("./example.public.key")
	require.NoError(t, err)

	// Parse the private key
	prKey, err := jwt.ParseRSAPrivateKeyFromPEM(privatekey)
	require.NoError(t, err)

	pbKey, err := jwt.ParseRSAPublicKeyFromPEM(publickey)
	require.NoError(t, err)

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
	require.NoError(t, err)

	t.Run("CreateToken", func(t *testing.T) {
		// Verify the access token is not empty
		require.NotEmpty(t, token.AccessToken)
		// Verify the refresh token is not empty
		require.NotEmpty(t, token.RefreshToken)
		// Verify the expiration time is approximately 1 hour from now
		expectedExpiration := time.Now().Add(time.Hour)
		if token.ExpiresAt.Before(expectedExpiration.Add(-time.Minute)) || token.ExpiresAt.After(expectedExpiration.Add(time.Minute)) {
			t.Errorf("Expected ExpiresAt to be approximately 1 hour from now, got %v", token.ExpiresAt)
		}
	})

	t.Run("Verify Token", func(t *testing.T) {
		valid, err := jwtService.VerifyToken(token.AccessToken, pbKey)
		require.NoError(t, err)
		require.Equal(t, true, valid)
	})
}
