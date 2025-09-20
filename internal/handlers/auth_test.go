package handlers

import (
	"bytes"
	"encoding/json"
	"github.com/iilun/f5-mock/internal/log"
	"github.com/iilun/f5-mock/pkg/cache"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestAuthHandler(t *testing.T) {

	defaultEnv := map[string]string{
		"F5_LOGIN_PROVIDER": "tmos",
		"F5_ADMIN_USERNAME": "admin",
		"F5_ADMIN_PASSWORD": "secret",
	}

	tests := []struct {
		name       string
		env        map[string]string // optional overrides
		body       any
		wantStatus int
		wantBody   string
	}{
		{
			name: "login disabled",
			env: map[string]string{
				"F5_LOGIN_PROVIDER": "",
				"F5_ADMIN_USERNAME": "admin",
				"F5_ADMIN_PASSWORD": "secret",
			},
			body:       map[string]string{},
			wantStatus: http.StatusForbidden,
			wantBody:   "login not available",
		},
		{
			name:       "invalid JSON body",
			body:       "not-json",
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid JSON body",
			env:        defaultEnv,
		},
		{
			name:       "missing fields",
			body:       map[string]string{"username": "admin"},
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid request",
			env:        defaultEnv,
		},
		{
			name: "bad username",
			body: map[string]string{
				"username":      "wrong",
				"password":      "secret",
				"loginProvider": "f5",
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   "unknown username",
			env:        defaultEnv,
		},
		{
			name: "bad password",
			body: map[string]string{
				"username":      "admin",
				"password":      "wrong",
				"loginProvider": "f5",
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   "bad authentication",
			env:        defaultEnv,
		},
		{
			name: "wrong login provider",
			body: map[string]string{
				"username":      "admin",
				"password":      "secret",
				"loginProvider": "wrong",
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   "unknown login provider",
			env:        defaultEnv,
		},
		{
			name: "successful login",
			body: map[string]string{
				"username":      "admin",
				"password":      "secret",
				"loginProvider": "tmos",
			},
			wantStatus: http.StatusOK,
			wantBody:   `"token"`,
			env:        defaultEnv,
		},
	}

	logger := log.New(true)
	defer logger.Close()

	_, _ = cache.New("")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				if v == "" {
					_ = os.Unsetenv(k)
				} else {
					_ = os.Setenv(k, v)
				}
			}

			handler := F5HandlerWrapper{LoginHandler{}, logger}
			reqBody := &bytes.Buffer{}

			switch v := tt.body.(type) {
			case string:
				reqBody.WriteString(v)
			default:
				json.NewEncoder(reqBody).Encode(v)
			}

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, handler.Route(), reqBody)

			h := handler.Handler()
			h.ServeHTTP(rr, req)

			require.Equal(t, tt.wantStatus, rr.Code)
			require.Contains(t, rr.Body.String(), tt.wantBody)

			if tt.wantStatus == http.StatusOK {
				var resp LoginResponse
				err := json.Unmarshal(rr.Body.Bytes(), &resp)
				require.NoError(t, err)
				// Verify token set in cache
				_, err = cache.GlobalCache.AuthTokens.Get(resp.Token.Token)
				require.NoError(t, err)
			}
		})
	}
}
