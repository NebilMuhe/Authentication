package symmetric

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSymmetricPaseto(t *testing.T) {
	// Create a new Paseto instance
	secretKey := []byte("symmetric-secret-key (size = 32)")
	pasetoService := NewSymmetricPasteo(
		Paseto{
			SecretKey:           secretKey,
			Isuuer:              "auth",
			TokenExpirationTime: time.Now().Add(time.Hour * 1),
		})
	// Create a token
	token, err := pasetoService.CreateToken("test-id", "test-footer", "test-audience", time.Now())
	// Check for errors
	require.NoError(t, err)

	t.Run("CreateToken", func(t *testing.T) {
		// Verify the token is not empty
		require.NotEmpty(t, token)
		// Verify the expiration time is approximately 1 hour from now
		expectedExpiration := time.Now().Add(time.Hour)
		if token.ExpiresAt.Before(expectedExpiration.Add(-time.Minute)) || token.ExpiresAt.After(expectedExpiration.Add(time.Minute)) {
			t.Errorf("Expected ExpiresAt to be approximately 1 hour from now, got %v", token.ExpiresAt)
		}
	})

	t.Run("VerifyToken", func(t *testing.T) {
		// Verify the token
		valid, err := pasetoService.VerifyToken(token.Token)
		require.NoError(t, err)
		// Check if the token is valid
		require.Equal(t, true, valid)
	},
	)
}
