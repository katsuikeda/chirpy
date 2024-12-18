package auth

import (
	"errors"
	"net/http"
	"strings"
)

func GetAPIKey(headers http.Header) (string, error) {
	const apiScheme = "ApiKey"

	authHeaderVal := headers.Get("Authorization")
	if authHeaderVal == "" {
		return "", errors.New("authorization header is missing or empty")
	}

	authParts := strings.Fields(authHeaderVal)
	if len(authParts) != 2 {
		return "", errors.New("authorization header format must be ApiKey {THE_KEY_HERE}")
	}

	scheme, apiKey := authParts[0], authParts[1]
	if !strings.EqualFold(scheme, apiScheme) {
		return "", errors.New("authorization scheme is not ApiKey")
	}

	// This condition might be redundant, but keep it for future-proofing and explicitness
	if apiKey == "" {
		return "", errors.New("api key is empty")
	}

	return apiKey, nil
}
