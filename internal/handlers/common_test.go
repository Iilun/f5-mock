package handlers

import (
	"github.com/iilun/f5-mock/internal/log"
	"github.com/iilun/f5-mock/pkg/cache"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
)

func TestAuthenticatedRequestMiddleware_ExternalAuth(t *testing.T) {
	// Enable external auth
	_ = os.Setenv("F5_LOGIN_PROVIDER", "tmos")
	defer func() { _ = os.Unsetenv("F5_LOGIN_PROVIDER") }()

	baseCache, _ := cache.New("")
	cache.GlobalCache = baseCache

	_ = cache.GlobalCache.AuthTokens.Set("valid-token", nil)

	logger := log.New(true)
	defer logger.Close()

	tests := []struct {
		name       string
		token      string
		wantStatus int
		wantBody   string
	}{
		{"missing token", "", http.StatusUnauthorized, "missing authentication"},
		{"invalid token", "bad-token", http.StatusUnauthorized, "invalid authentication"},
		{"valid token", "valid-token", http.StatusOK, "ok"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.token != "" {
				req.Header.Set("X-F5-Auth-Token", tt.token)
			}

			middleware := authenticatedRequestMiddleware(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("ok"))
			})

			middleware(rr, req)

			require.Equal(t, tt.wantStatus, rr.Code)
			require.Contains(t, rr.Body.String(), tt.wantBody)
		})
	}
}

func TestAuthenticatedRequestMiddleware_BasicAuth(t *testing.T) {
	// Disable external auth
	_ = os.Unsetenv("F5_LOGIN_PROVIDER")
	_ = os.Setenv("F5_ADMIN_USERNAME", "admin")
	_ = os.Setenv("F5_ADMIN_PASSWORD", "secret")

	logger := log.New(true)
	defer logger.Close()

	tests := []struct {
		name       string
		username   string
		password   string
		wantStatus int
		wantBody   string
	}{
		{"missing auth header", "", "", http.StatusUnauthorized, "missing authentication"},
		{"invalid creds", "admin", "wrong", http.StatusUnauthorized, "bad authentication"},
		{"valid creds", "admin", "secret", http.StatusOK, "ok"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.username != "" {
				req.SetBasicAuth(tt.username, tt.password)
			}

			middleware := authenticatedRequestMiddleware(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("ok"))
			})

			middleware(rr, req)

			require.Equal(t, tt.wantStatus, rr.Code)
			require.Contains(t, rr.Body.String(), tt.wantBody)
		})
	}
}

func TestApplyVersionMiddleware(t *testing.T) {
	logger := log.New(true)
	defer logger.Close()

	tests := []struct {
		name            string
		urlVersion      string
		envVersion      string
		error           string
		expectedVersion string
	}{
		{
			name:            "invalid env version and no version in url",
			urlVersion:      "",
			envVersion:      "abc",
			error:           "{\"message\":\"invalid version\"}",
			expectedVersion: "",
		},
		{
			name:            "invalid env version and invalid version in url",
			urlVersion:      "abc",
			envVersion:      "abc",
			error:           "{\"message\":\"invalid version\"}",
			expectedVersion: "",
		},
		{
			name:            "invalid env version and valid version in url",
			urlVersion:      "16.2",
			envVersion:      "abc",
			error:           "",
			expectedVersion: "16",
		},
		{
			name:            "valid env version and no version in url",
			urlVersion:      "",
			envVersion:      "16.3",
			error:           "",
			expectedVersion: "16",
		},
		{
			name:            "valid env version and valid version in url",
			urlVersion:      "18.0.0.0",
			envVersion:      "16.3",
			error:           "",
			expectedVersion: "18",
		},
		{
			name:            "no env nor url version",
			urlVersion:      "",
			envVersion:      "",
			error:           "",
			expectedVersion: "17",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			url := "/"
			if tt.urlVersion != "" {
				url += "?ver=" + tt.urlVersion
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)

			if tt.envVersion != "" {
				_ = os.Setenv("F5_BASE_VERSION", tt.envVersion)
			} else {
				_ = os.Unsetenv("F5_BASE_VERSION")
			}

			middleware := applyVersionMiddleware(func(w http.ResponseWriter, r *http.Request) {
				version, ok := r.Context().Value(log.ContextVersion).(int)
				if !ok {
					f5Error(w, r, http.StatusInternalServerError, "invalid version in context")
					return
				}

				_, _ = w.Write([]byte(strconv.Itoa(version)))
			})

			middleware(rr, req)

			if tt.error != "" {
				require.Equal(t, http.StatusBadRequest, rr.Code)
				require.Equal(t, tt.error, rr.Body.String())
			} else {
				require.Equal(t, tt.expectedVersion, rr.Body.String())
			}
		})
	}
}
