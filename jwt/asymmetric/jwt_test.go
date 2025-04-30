package asymmetric

import (
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAsymmetricJWT(t *testing.T) {
	privatekey, err := os.ReadFile("./example.private.key")
	assertNoError(t, err)
	publickey, err := os.ReadFile("./example.public.key")
	assertNoError(t, err)

	// Parse the private key
	prKey, err := jwt.ParseRSAPrivateKeyFromPEM(privatekey)
	assertNoError(t, err)

	pbKey, err := jwt.ParseRSAPublicKeyFromPEM(publickey)
	assertNoError(t, err)

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
	assertNoError(t, err)

	t.Run("CreateToken", func(t *testing.T) {
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

	t.Run("Verify Token", func(t *testing.T) {
		valid, err := jwtService.VerifyToken(token.AccessToken, pbKey)
		assertNoError(t, err)
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
