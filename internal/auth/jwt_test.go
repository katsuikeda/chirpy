// auth_test.go
package auth

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestValidateJWT(t *testing.T) {
	secretKey := "test-secret-key"
	validUserID := uuid.New()

	validToken, err := MakeJWT(validUserID, secretKey, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create valid JWT: %v", err)
	}

	invalidSignatureToken, err := MakeJWT(validUserID, "wrong-secret-key", time.Hour)
	if err != nil {
		t.Fatalf("Failed to create token with invalid signature: %v", err)
	}

	expiredToken, err := MakeJWT(validUserID, secretKey, -time.Hour)
	if err != nil {
		t.Fatalf("Failed to create expired JWT: %v", err)
	}

	tokenWithInvalidIssuer := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "invalid-issuer",
		Subject:   validUserID.String(),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour)),
	})
	tokenWithInvalidIssuerString, err := tokenWithInvalidIssuer.SignedString([]byte(secretKey))
	if err != nil {
		t.Fatalf("Failed to create token with invalid issuer: %v", err)
	}

	malformedToken := "this.is.not.a.valid.token"

	tokenWithInvalidSubject := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   "invalid-uuid",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour)),
	})
	tokenWithInvalidSubjectString, err := tokenWithInvalidSubject.SignedString([]byte(secretKey))
	if err != nil {
		t.Fatalf("Failed to create token with invalid subject: %v", err)
	}

	tests := []struct {
		name        string
		token       string
		secret      string
		wantUserID  uuid.UUID
		wantErr     bool
		errorString string
	}{
		{
			name:       "Valid Token",
			token:      validToken,
			secret:     secretKey,
			wantUserID: validUserID,
			wantErr:    false,
		},
		{
			name:        "Invalid Signature",
			token:       invalidSignatureToken,
			secret:      secretKey,
			wantUserID:  uuid.Nil,
			wantErr:     true,
			errorString: "couldn't parse token",
		},
		{
			name:        "Expired Token",
			token:       expiredToken,
			secret:      secretKey,
			wantUserID:  uuid.Nil,
			wantErr:     true,
			errorString: "token is expired",
		},
		{
			name:        "Invalid Issuer",
			token:       tokenWithInvalidIssuerString,
			secret:      secretKey,
			wantUserID:  uuid.Nil,
			wantErr:     true,
			errorString: "invalid issuer",
		},
		{
			name:        "Malformed Token",
			token:       malformedToken,
			secret:      secretKey,
			wantUserID:  uuid.Nil,
			wantErr:     true,
			errorString: "couldn't parse token",
		},
		{
			name:        "Invalid Subject",
			token:       tokenWithInvalidSubjectString,
			secret:      secretKey,
			wantUserID:  uuid.Nil,
			wantErr:     true,
			errorString: "couldn't parse subject",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserID, err := ValidateJWT(tt.token, tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateJWT() expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorString) {
					t.Errorf("ValidateJWT() error = %v, expected substring %v", err, tt.errorString)
				}
				return
			}
			if gotUserID != tt.wantUserID {
				t.Errorf("ValidateJWT() = %v, want %v", gotUserID, tt.wantUserID)
			}
		})
	}
}

func TestGetBearerToken(t *testing.T) {
	validToken := "valid.token.here"

	tests := []struct {
		name        string
		headers     http.Header
		wantToken   string
		wantErr     bool
		errorString string
	}{
		{
			name:      "Valid Authorization Header",
			headers:   http.Header{"Authorization": []string{"Bearer " + validToken}},
			wantToken: validToken,
			wantErr:   false,
		},
		{
			name:        "Missing Authorization Header",
			headers:     http.Header{},
			wantErr:     true,
			errorString: "authorization header is missing or empty",
		},
		{
			name:        "Incorrect Scheme",
			headers:     http.Header{"Authorization": []string{"Basic " + validToken}},
			wantErr:     true,
			errorString: "authorization scheme is not Bearer",
		},
		{
			name:      "Multiple Spaces Between Scheme and Token",
			headers:   http.Header{"Authorization": []string{"Bearer    " + validToken}},
			wantToken: validToken,
			wantErr:   false,
		},
		{
			name:      "Tabs and Newlines in Header",
			headers:   http.Header{"Authorization": []string{"Bearer\t" + validToken}},
			wantToken: validToken,
			wantErr:   false,
		},
		{
			name:        "Empty Token",
			headers:     http.Header{"Authorization": []string{"Bearer "}},
			wantErr:     true,
			errorString: "authorization header format must be Bearer {token}",
		},
		{
			name:        "Malformed Token (Incorrect JWT Structure)",
			headers:     http.Header{"Authorization": []string{"Bearer malformedtoken"}},
			wantErr:     true,
			errorString: "invalid bearer token format",
		},
		{
			name:        "Bearer with Multiple Tokens",
			headers:     http.Header{"Authorization": []string{"Bearer token1 token2"}},
			wantErr:     true,
			errorString: "authorization header format must be Bearer {token}",
		},
		{
			name:        "Bearer with Only Scheme",
			headers:     http.Header{"Authorization": []string{"Bearer"}},
			wantErr:     true,
			errorString: "authorization header format must be Bearer {token}",
		},
		{
			name:      "Bearer with Leading and Trailing Spaces",
			headers:   http.Header{"Authorization": []string{"   Bearer " + validToken + "   "}},
			wantToken: validToken,
			wantErr:   false,
		},
		{
			name:      "Bearer with Newline Character",
			headers:   http.Header{"Authorization": []string{"Bearer\n" + validToken}},
			wantToken: validToken,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotToken, err := GetBearerToken(tt.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetBearerToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetBearerToken() expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorString) {
					t.Errorf("GetBearerToken() error = %v, expected substring %v", err, tt.errorString)
				}
				return
			}
			if gotToken != tt.wantToken {
				t.Errorf("GetBearerToken() = %v, want %v", gotToken, tt.wantToken)
			}
		})
	}
}
