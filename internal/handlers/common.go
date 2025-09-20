package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/iilun/f5-mock/internal/log"
	"github.com/iilun/f5-mock/pkg/cache"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type F5Error struct {
	Message string `json:"message"`
}

func f5Error(w http.ResponseWriter, r *http.Request, status int, message string, args ...any) {
	logger := loggerFromRequest(r)
	logger.Error(message, args...)

	formattedMsg := fmt.Sprintf(message, args...)
	err := F5Error{Message: formattedMsg}
	bytes, _ := json.Marshal(err)
	w.WriteHeader(status)
	_, _ = w.Write(bytes)
}

func enforceContentTypeMiddleWare(ct string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := checkContentType(r, ct)
		if err != nil {
			f5Error(w, r, http.StatusUnsupportedMediaType, err.Error())
			return
		}

		next(w, r)
	}
}

func checkContentType(r *http.Request, ct string) error {
	if r.Header.Get("Content-Type") != ct {
		return fmt.Errorf("invalid content-type: expected %s", ct)
	}
	return nil
}

func parsePath(path string) (string, string, error) {
	splitProfile := strings.Split(path, "~")
	if len(splitProfile) != 3 {
		return "", "", errors.New("invalid path")
	}

	return splitProfile[1], splitProfile[2], nil
}

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
			f5Error(w, r, http.StatusUnauthorized, err.Error())
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

type loggerCtxKey struct{}

func loggingMiddleware(logger log.Logger, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestId := uuid.New()

		newLogger := logger.With(
			log.ContextRequestId, requestId,
			"url", r.URL.String(),
			"method", r.Method,
		)

		ctx := context.WithValue(r.Context(), loggerCtxKey{}, newLogger)

		next(w, r.WithContext(ctx))
	}
}

func loggerFromRequest(r *http.Request) log.Logger {
	if l, ok := r.Context().Value(loggerCtxKey{}).(log.Logger); ok {
		return l
	}
	return log.Default
}
