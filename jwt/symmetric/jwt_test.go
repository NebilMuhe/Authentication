package symmetric

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestSymmetricJWT(t *testing.T) {
	// Create a new JWT instance
	secretKey := []byte("test-secret-key")
	jwtService := NewSymmetricJWT(
		JWT{
			SecretKey:                  secretKey,
			SigningMethod:              jwt.SigningMethodHS256,
			AccessTokenExpirationTime:  time.Now().Add(time.Hour * 1),
			RefreshTokenExpirationTime: time.Now().Add(time.Hour * 24),
			Issuer:                     "auth",
		})
	// Create a token
	token, err := jwtService.CreateToken("test-id", time.Now(), "test-audience")
	// Check for errors
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

	t.Run("VerifyToken", func(t *testing.T) {
		// Verify the token
		valid, err := jwtService.VerifyToken(token.AccessToken)
		require.NoError(t, err)
		// Check if the token is valid
		require.Equal(t, true, valid)
	})
}
