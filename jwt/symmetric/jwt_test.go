package symmetric

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

	t.Run("CreateToken", func(t *testing.T) {
		// Create a token
		token, err := jwtService.CreateToken("test-id", time.Now(), "test-audience")
		// Check for errors
		assertNoError(t, err)
		// Verify the access token is not empty
		assertNotEmpty(t, token.AccessToken)
		// Verify the refresh token is not empty
		assertNotEmpty(t, token.RefreshToken)
		// Verify the expiration time is approximately 1 hour from now
		expectedExpiration := time.Now().Add(time.Hour)
		if token.ExpiresAt.Before(expectedExpiration.Add(-time.Minute)) || token.ExpiresAt.After(expectedExpiration.Add(time.Minute)) {
			t.Errorf("Expected ExpiresAt to be approximately 1 hour from now, got %v", token.ExpiresAt)
		}
	})

	t.Run("VerifyToken", func(t *testing.T) {
		// Create a token
		token, err := jwtService.CreateToken("test-id", time.Now(), "test-audience")
		assertNoError(t, err)
		// Verify the token
		valid, err := jwtService.VerifyToken(token.AccessToken)
		assertNoError(t, err)
		// Check if the token is valid
		assertEqual(t, true, valid)
	})
}

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}
}

func assertNotEmpty(t *testing.T, str string) {
	if str == "" {
		t.Errorf("Expected string to be non-empty")
	}
}

func assertEqual(t *testing.T, expected, actual any) {
	if expected != actual {
		t.Errorf("Expected %v, but got %v", expected, actual)
	}
}
