package handlers

import (
	"encoding/json"
	"github.com/iilun/f5-mock/internal/log"
	"github.com/iilun/f5-mock/pkg/cache"
	"github.com/iilun/f5-mock/pkg/models"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestAS3Handler(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		profiles    []*models.ClientSSLProfile
		wantStatus  int
		wantBody    string
		disableAuth bool
	}{
		{
			name:       "empty cache returns empty JSON",
			method:     http.MethodGet,
			profiles:   nil,
			wantStatus: http.StatusOK,
			wantBody:   `{}`,
		},
		{
			name:   "single profile one partition",
			method: http.MethodGet,
			profiles: []*models.ClientSSLProfile{
				{Name: "prof1", Partition: "Common", Cert: "/etc/certs/cert1.crt"},
			},
			wantStatus: http.StatusOK,
			wantBody:   `{"Common":{"class":"Tenant","prof1":{"class":"Application","cert1.crt":{"class":"Certificate"}}}}`,
		},
		{
			name:   "two profiles same partition",
			method: http.MethodGet,
			profiles: []*models.ClientSSLProfile{
				{Name: "prof1", Partition: "Common", Cert: "c1.crt"},
				{Name: "prof2", Partition: "Common", Cert: "/tmp/c2.crt"},
			},
			wantStatus: http.StatusOK,
			wantBody:   `{"Common":{"class":"Tenant","prof1":{"class":"Application","c1.crt":{"class":"Certificate"}},"prof2":{"class":"Application","c2.crt":{"class":"Certificate"}}}}`,
		},
		{
			name:   "profiles in different partitions",
			method: http.MethodGet,
			profiles: []*models.ClientSSLProfile{
				{Name: "prof1", Partition: "Common", Cert: "c1.crt"},
				{Name: "prof2", Partition: "TenantA", Cert: "c2.crt"},
			},
			wantStatus: http.StatusOK,
			// Order of keys in JSON is not guaranteed, so we check via unmarshalling
			wantBody: `{
				"Common": {"class":"Tenant","prof1":{"class":"Application","c1.crt":{"class":"Certificate"}}},
				"TenantA": {"class":"Tenant","prof2":{"class":"Application","c2.crt":{"class":"Certificate"}}}
			}`,
		},
		{
			name:       "non-GET method",
			method:     http.MethodPost,
			profiles:   nil,
			wantStatus: http.StatusOK,
			wantBody:   ``,
		},
		{
			name:        "auth is enforced",
			method:      http.MethodPost,
			profiles:    nil,
			wantStatus:  http.StatusUnauthorized,
			wantBody:    ``,
			disableAuth: true,
		},
	}

	_, _ = cache.New("")

	logger := log.New(true)
	defer logger.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			cache.GlobalCache.ClientSSLProfiles = tt.profiles

			h := F5HandlerWrapper{AS3Handler{}, logger}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, h.Route(), nil)
			if !tt.disableAuth {
				req.SetBasicAuth(os.Getenv("F5_ADMIN_USERNAME"), os.Getenv("F5_ADMIN_PASSWORD"))
			}

			h.Handler()(w, req)

			require.Equal(t, tt.wantStatus, w.Code, "status mismatch")

			if tt.wantBody != "" {
				var gotJSON, wantJSON map[string]any
				_ = json.Unmarshal(w.Body.Bytes(), &gotJSON)
				_ = json.Unmarshal([]byte(tt.wantBody), &wantJSON)
				require.Equal(t, wantJSON, gotJSON, "json body mismatch")
			}
		})
	}
}
