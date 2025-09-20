package handlers

import (
	"encoding/json"
	"github.com/iilun/f5-mock/pkg/cache"
	"github.com/iilun/f5-mock/pkg/models"
	"net/http"
	"path/filepath"
)

type AS3Handler struct{}

func (h AS3Handler) Route() string {
	return "/mgmt/shared/appsvcs/declare"
}

func (h AS3Handler) Handler() http.HandlerFunc {
	return authenticatedRequestMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			byPartition := make(map[string][]*models.ClientSSLProfile)
			for _, p := range cache.GlobalCache.ClientSSLProfiles {
				base := byPartition[p.Partition]
				base = append(base, p)
				byPartition[p.Partition] = base
			}

			response := make(map[string]any)

			for partition, profiles := range byPartition {
				tenantMap := make(map[string]any)
				tenantMap["class"] = "Tenant"

				for _, p := range profiles {
					applicationMap := make(map[string]any)
					applicationMap["class"] = "Application"

					certificateMap := make(map[string]any)
					certificateMap["class"] = "Certificate"

					applicationMap[filepath.Base(p.Cert)] = certificateMap

					tenantMap[p.Name] = applicationMap
				}

				response[partition] = tenantMap
			}

			respBytes, err := json.Marshal(response)
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "%v", err)
				return
			}

			_, err = w.Write(respBytes)
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "%v", err)
				return
			}
			return
		}
	})
}
