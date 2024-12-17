package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const issuer = "chirpy"

// MakeJWT creates a JWT token for an authenticated user.
// This should only be called after successful user authentication.
func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	signingKey := []byte(tokenSecret)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   userID.String(),
	})

	signedString, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT, %w", err)
	}

	return signedString, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	registeredClaims := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(
		tokenString,
		&registeredClaims,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(tokenSecret), nil
		})
	if err != nil {
		return uuid.Nil, fmt.Errorf("couldn't parse token: %w", err)
	}

	if !token.Valid {
		return uuid.Nil, errors.New("invalid token")
	}
	if registeredClaims.ExpiresAt.Time.Before(time.Now()) {
		return uuid.Nil, errors.New("token is expired")
	}
	if registeredClaims.Issuer != issuer {
		return uuid.Nil, errors.New("invalid issuer")
	}

	userID, err := uuid.Parse(registeredClaims.Subject)
	if err != nil {
		return uuid.Nil, fmt.Errorf("couldn't parse subject: %w", err)
	}
	return userID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	const bearerScheme = "Bearer"

	authHeaderVal := headers.Get("Authorization")
	if authHeaderVal == "" {
		return "", errors.New("authorization header is missing or empty")
	}

	authParts := strings.Fields(authHeaderVal)
	if len(authParts) != 2 {
		return "", errors.New("authorization header format must be Bearer {token}")
	}

	scheme, token := authParts[0], authParts[1]
	if !strings.EqualFold(scheme, bearerScheme) {
		return "", errors.New("authorization scheme is not Bearer")
	}

	// This condition might be redundant, but keep it for future-proofing and explicitness
	if token == "" {
		return "", errors.New("bearer token is empty")
	}

	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 3 {
		return "", errors.New("invalid bearer token format")
	}

	return token, nil
}
