package handlers

import (
	"F5Mock/pkg/cache"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func f5Error(w http.ResponseWriter, status int, message string, args ...any) {
	http.Error(w, fmt.Sprintf(message, args...), status)
}

func jsonPayloadMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only POST allowed
		if r.Method != http.MethodPost {
			f5Error(w, http.StatusMethodNotAllowed, "only POST allowed")
			return
		}

		// Require JSON content type
		if r.Header.Get("Content-Type") != "application/json" {
			f5Error(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
			return
		}

		next(w, r)
	}
}

func authenticatedRequestMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		externalAuthEnabled := os.Getenv("F5_LOGIN_PROVIDER") != ""
		if externalAuthEnabled {
			// Check the token
			authToken := r.Header.Get("X-F5-Auth-Token")
			if authToken == "" {
				f5Error(w, http.StatusUnauthorized, "not authenticated")
				return
			}
			_, err := cache.GlobalCache.AuthTokens.Get(authToken)
			if err != nil {
				// Token not found
				f5Error(w, http.StatusUnauthorized, "invalid auth")
				return
			}
		} else {
			// Check the authorization header
			basicAuth := r.Header.Get("Authorization")
			if basicAuth == "" {
				f5Error(w, http.StatusUnauthorized, "not authenticated")
				return
			}
			basicAuthB64, found := strings.CutPrefix(basicAuth, "Basic ")
			if !found {
				f5Error(w, http.StatusUnauthorized, "unsupported auth header format")
				return
			}
			b64Payload, err := base64.StdEncoding.DecodeString(basicAuthB64)
			if err != nil {
				// Token not found
				f5Error(w, http.StatusUnauthorized, "malformed basic auth")
				return
			}
			splitAuth := strings.Split(string(b64Payload), ":")
			if len(splitAuth) != 2 {
				f5Error(w, http.StatusUnauthorized, "malformed basic auth payload")
				return
			}
			err = checkAuth(splitAuth[0], splitAuth[1])
			if err != nil {
				f5Error(w, http.StatusUnauthorized, err.Error())
				return
			}
		}

		next(w, r)
	}
}
