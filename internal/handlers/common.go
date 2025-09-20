package handlers

import (
	"context"
	"fmt"
	"github.com/iilun/f5-mock/internal/log"
	"github.com/iilun/f5-mock/pkg/cache"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func globalAuthCheck(r *http.Request) error {
	externalAuthEnabled := os.Getenv("F5_LOGIN_PROVIDER") != ""
	if externalAuthEnabled {
		// Check the token
		authToken := r.Header.Get("X-F5-Auth-Token")
		if authToken == "" {
			return fmt.Errorf("missing authentication")
		}
		_, err := cache.GlobalCache.AuthTokens.Get(authToken)
		if err != nil {
			// Token not found
			return fmt.Errorf("invalid authentication")
		}
	} else {
		// Check the authorization header
		username, password, found := r.BasicAuth()
		if !found {
			return fmt.Errorf("missing authentication")
		}
		err := checkAuth(username, password)
		if err != nil {
			return err
		}
	}
	return nil
}

func authenticatedRequestMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := globalAuthCheck(r)
		if err != nil {
			f5Error(w, r, http.StatusUnauthorized, "%v", err)
			return
		}

		next(w, r)
	}
}

func applyVersionMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		version := r.URL.Query().Get("ver")

		if version == "" {
			version = os.Getenv("F5_BASE_VERSION")
		}

		if version == "" {
			version = "17.0.0.0"
		}

		major, _, _ := strings.Cut(version, ".")

		majorInt, err := strconv.Atoi(major)
		if err != nil {
			f5Error(w, r, http.StatusBadRequest, "invalid version")
			return
		}

		ctx := context.WithValue(r.Context(), log.ContextVersion, majorInt)

		next(w, r.WithContext(ctx))
	}
}
