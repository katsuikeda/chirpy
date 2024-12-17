package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func MakeRefreshToken() (string, error) {
	randomData := make([]byte, 32)
	_, err := rand.Read(randomData)
	if err != nil {
		return "", fmt.Errorf("couldn't generate random data: %w", err)
	}

	refreshToken := hex.EncodeToString(randomData)
	return refreshToken, nil
}

func GetRefreshToken(headers http.Header) (string, error) {
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

	if len(token) != 64 {
		return "", errors.New("invalid bearer token format")
	}

	return token, nil
}
