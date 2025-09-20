package handlers

import (
	"bytes"
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

func TestClientSSLHandler(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		path          string
		profiles      []*models.ClientSSLProfile
		existingFiles []string
		body          any
		headers       map[string]string
		wantStatus    int
		wantBody      string
		disableAuth   bool
	}{
		{
			name:       "invalid path param",
			method:     http.MethodGet,
			path:       "invalid-path",
			profiles:   nil,
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid",
		},
		{
			name:       "profile not found",
			method:     http.MethodGet,
			path:       "~Common~notfound",
			profiles:   nil,
			wantStatus: http.StatusNotFound,
			wantBody:   "could not find profile",
		},
		{
			name:   "GET success",
			method: http.MethodGet,
			path:   "~Common~prof1",
			profiles: []*models.ClientSSLProfile{
				{Name: "prof1", Partition: "Common", Cert: "c1.crt", Key: "k1.key"},
			},
			wantStatus: http.StatusOK,
			wantBody:   `"cert":"c1.crt"`,
		},
		{
			name:   "PATCH wrong content type",
			method: http.MethodPatch,
			path:   "~Common~prof1",
			profiles: []*models.ClientSSLProfile{
				{Name: "prof1", Partition: "Common"},
			},
			headers:    map[string]string{"Content-Type": "text/plain"},
			wantStatus: http.StatusUnsupportedMediaType,
			wantBody:   "expected application/json",
		},
		{
			name:   "PATCH invalid JSON",
			method: http.MethodPatch,
			path:   "~Common~prof1",
			profiles: []*models.ClientSSLProfile{
				{Name: "prof1", Partition: "Common"},
			},
			headers:    map[string]string{"Content-Type": "application/json"},
			body:       "not-json",
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid patch request",
		},
		{
			name:   "PATCH invalid cert",
			method: http.MethodPatch,
			path:   "~Common~prof1",
			profiles: []*models.ClientSSLProfile{
				{Name: "prof1", Partition: "Common"},
			},
			headers:       map[string]string{"Content-Type": "application/json"},
			body:          map[string]string{"cert": "bad-cert", "key": "k1.key"},
			wantStatus:    http.StatusBadRequest,
			wantBody:      "Field validation for 'Cert' failed on the 'existingcertfile' tag",
			existingFiles: []string{"/keys/k1.key"},
		},
		{
			name:   "PATCH success",
			method: http.MethodPatch,
			path:   "~Common~prof1",
			profiles: []*models.ClientSSLProfile{
				{Name: "prof1", Partition: "Common"},
			},
			headers:       map[string]string{"Content-Type": "application/json"},
			body:          map[string]string{"cert": "c2.crt", "key": "k2.key"},
			wantStatus:    http.StatusOK,
			wantBody:      `"cert":"c2.crt"`,
			existingFiles: []string{"/keys/k2.key", "/certs/c2.crt"},
		},
		{
			name:   "invalid method",
			method: http.MethodDelete,
			path:   "~Common~prof1",
			profiles: []*models.ClientSSLProfile{
				{Name: "prof1", Partition: "Common"},
			},
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "invalid method",
		},
		{
			name:        "auth enforced",
			method:      http.MethodGet,
			path:        "~Common~prof1",
			profiles:    nil,
			wantStatus:  http.StatusUnauthorized,
			wantBody:    "",
			disableAuth: true,
		},
	}

	_, _ = cache.New("")

	logger := log.New(true)
	defer logger.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.GlobalCache.ClientSSLProfiles = tt.profiles

			for _, f := range tt.existingFiles {
				_, _ = cache.GlobalCache.Fs.WriteFile(f, nil)
			}

			h := F5HandlerWrapper{ClientSSLHandler{}, logger}

			reqBody := &bytes.Buffer{}
			switch v := tt.body.(type) {
			case string:
				reqBody.WriteString(v)
			case map[string]string:
				_ = json.NewEncoder(reqBody).Encode(v)
			}

			req := httptest.NewRequest(tt.method, "/clientssl/"+tt.path, reqBody)
			req.SetPathValue("profile", tt.path)

			if !tt.disableAuth {
				req.SetBasicAuth(os.Getenv("F5_ADMIN_USERNAME"), os.Getenv("F5_ADMIN_PASSWORD"))
			}

			if tt.headers != nil {
				for k, v := range tt.headers {
					req.Header.Set(k, v)
				}
			}

			rr := httptest.NewRecorder()
			h.Handler()(rr, req)

			require.Equal(t, tt.wantStatus, rr.Code)

			if tt.wantBody != "" {
				require.Contains(t, rr.Body.String(), tt.wantBody)
			}
		})
	}
}
