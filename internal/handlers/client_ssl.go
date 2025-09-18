package handlers

import (
	"F5Mock/pkg/cache"
	"F5Mock/pkg/models"
	"encoding/json"
	"net/http"
	"strings"
)

type ClientSSLHandler struct{}

func (h *ClientSSLHandler) Route() string {
	return "tm/ltm/profile/client-ssl"
}

func (h *ClientSSLHandler) Handler() http.HandlerFunc {
	return authenticatedRequestMiddleware(func(w http.ResponseWriter, r *http.Request) {

		if r.Method == http.MethodGet {
			// Parse request params
			queryParams := r.URL.Query()
			fieldSelect := queryParams.Get("$select")
			filter := queryParams.Get("$filter")

			filteredItems := cache.GlobalCache.ClientSSLProfiles
			if filter != "" {
				partition, found := strings.CutPrefix(filter, "partition eq ")
				if !found {
					f5Error(w, http.StatusBadRequest, "unsupported $filter")
					return
				}
				filteredItems = []models.ClientSSLProfile{}
				for _, profile := range cache.GlobalCache.ClientSSLProfiles {
					if profile.Partition == partition {
						filteredItems = append(filteredItems, profile)
					}
				}
			}

			if fieldSelect != "" {
				// Marshal as json
				json.Marshal()
			}

		}
	})
}

func filterFields(profile models.ClientSSLProfile, selectField string) (map[string]any, error) {
	bytes, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	var asMap map[string]any
	err = json.Unmarshal(bytes, &asMap)
	if err != nil {
		return nil, err
	}
	if selectField != "" {
		var filteredMap map[string]any
		for key, value := range asMap {
			if key == selectField {
				filteredMap[key] = value
			}
		}
		asMap = filteredMap
	}
	return asMap, nil
}

type ClientSSLListResponse struct {
	Items []models.ClientSSLProfile `json:"items"`
}
