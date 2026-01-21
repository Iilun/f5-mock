package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"

	"github.com/iilun/f5-mock/pkg/cache"
	"github.com/iilun/f5-mock/pkg/models"
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
					if len(p.CertKeyChain) > 0 && p.CertKeyChain[0].Chain != "" {
						certificateMap["chainCA"] = p.CertKeyChain[0].Chain
					}

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
		case http.MethodPatch:
			// Read body
			bytes, err := io.ReadAll(r.Body)
			if err != nil {
				f5Error(w, r, http.StatusInternalServerError, "could not read body")
				return
			}

			var requests []PatchRequest
			err = json.Unmarshal(bytes, &requests)
			if err != nil {
				f5Error(w, r, http.StatusBadRequest, "invalid JSON body")
				return
			}

			for _, request := range requests {
				partition, profileName, err := parseAS3Path(request.Path)

				if err != nil {
					f5Error(w, r, http.StatusBadRequest, "%v", err)
					return
				}

				profile := findProfile(partition, profileName)
				if profile == nil {
					f5Error(w, r, http.StatusBadRequest, "profile %s not found", profileName)
					return
				}

				switch request.Op {
				case "replace":
					class, ok := request.Value["class"].(string)
					if !ok {
						f5Error(w, r, http.StatusBadRequest, "missing class for value")
						return
					}

					switch class {
					case "Certificate":
						// TODO: add other fields support
						caChain, ok := request.Value["chainCA"]
						if !ok {
							return
						}
						caChainStr, ok := caChain.(string)
						if !ok {
							f5Error(w, r, http.StatusBadRequest, "chainCA must be a string")
							return
						}

						profile.CertKeyChain[0].Chain = caChainStr
						return
					default:
						f5Error(w, r, http.StatusBadRequest, "class %s unsupported", class)
						return
					}
				default:
					f5Error(w, r, http.StatusBadRequest, "patch op %s unsupported", request.Op)
					return
				}
			}
		}
	})
}

type PatchRequest struct {
	Op    string         `validate:"required"`
	Path  string         `validate:"required"`
	Value map[string]any `validate:"required"`
}
