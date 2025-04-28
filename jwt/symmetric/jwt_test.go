package symmetric

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestCreateToken(t *testing.T) {
	Secretkey := []byte("test-secret-key-for-testing")
	jwtService := NewSymmetricJWT(
		JWT{
			SecretKey:                  Secretkey,
			SigningMethod:              jwt.SigningMethodHS256,
			AccessTokenExpirationTime:  time.Now().Add(time.Hour * 1),
			RefreshTokenExpirationTime: time.Now().Add(time.Hour * 24),
			Issuer:                     "auth",
		},
	)

	// Test case: Create a token
	token, err := jwtService.CreateToken("test-id", time.Now(), "test-audience")
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Verify the access token is not empty
	if token.AccessToken == "" {
		t.Errorf("Expected AccessToken to be non-empty")
	}

	// Verify the refresh token is not empty
	if token.RefreshToken == "" {
		t.Errorf("Expected RefreshToken to be non-empty")
	}

	// Verify the expiration time is approximately 1 hour from now
	expectedExpiration := time.Now().Add(time.Hour)
	if token.ExpiresAt.Before(expectedExpiration.Add(-time.Minute)) || token.ExpiresAt.After(expectedExpiration.Add(time.Minute)) {
		t.Errorf("Expected ExpiresAt to be approximately 1 hour from now, got %v", token.ExpiresAt)
	}

	// Verify the access token contains the expected claims
	parsedToken, err := jwt.ParseWithClaims(token.AccessToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		return Secretkey, nil
	})
	if err != nil {
		t.Fatalf("Failed to parse access token: %v", err)
	}

	claims, ok := parsedToken.Claims.(*jwt.RegisteredClaims)
	if !ok || !parsedToken.Valid {
		t.Fatalf("Failed to parse claims or token is invalid")
	}

	if claims.Subject != "test-id" {
		t.Errorf("Expected Subject to be 'test-id', got %v", claims.Subject)
	}

	if claims.Issuer != "auth" {
		t.Errorf("Expected Issuer to be 'auth', got %v", claims.Issuer)
	}

	if claims.Audience[0] != "test-audience" {
		t.Errorf("Expected Audience to contain 'app', got %v", claims.Audience)
	}
}
