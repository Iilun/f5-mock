package handlers

import (
	"F5Mock/pkg/cache"
	"encoding/json"
	"errors"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"io"
	"net/http"
	"os"
)

type LoginHandler struct{}

func (h LoginHandler) Route() string {
	return "/mgmt/shared/authn/login"
}

func (h LoginHandler) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expectedLoginProvider := os.Getenv("F5_LOGIN_PROVIDER")
		// FIXME: check if htis is how it works
		if expectedLoginProvider == "" {
			// This endpoint is disabled if external auth not enabled
			f5Error(w, http.StatusForbidden, "login not available")
			return
		}

		// Read body
		bytes, err := io.ReadAll(r.Body)
		if err != nil {
			f5Error(w, http.StatusInternalServerError, "could not read body")
			return
		}

		var request LoginRequest
		err = json.Unmarshal(bytes, &request)
		if err != nil {
			f5Error(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		validate := validator.New(validator.WithRequiredStructEnabled())

		err = validate.Struct(request)
		if err != nil {
			f5Error(w, http.StatusBadRequest, "invalid request")
			return
		}

		err = checkAuth(request.Username, request.Password)
		if err != nil {
			f5Error(w, http.StatusBadRequest, err.Error())
			return
		}

		if request.LoginProvider != expectedLoginProvider {
			f5Error(w, http.StatusBadRequest, "unknown login provider")
			return
		}

		// All validations are successful, generate token
		token := uuid.New()
		err = cache.GlobalCache.AuthTokens.Set(token.String(), nil)
		if err != nil {
			f5Error(w, http.StatusInternalServerError, "could not set cache entry")
			return
		}

		response := LoginResponse{Token: Token{token.String()}}

		jsonBytes, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			f5Error(w, http.StatusInternalServerError, "could not marshal json")
			return
		}

		_, err = w.Write(jsonBytes)
		if err != nil {
			f5Error(w, http.StatusInternalServerError, "could not marshal json")
			return
		}
		return
	}
}

func checkAuth(username, password string) error {
	expectedUsername := os.Getenv("F5_ADMIN_USERNAME")
	expectedPassword := os.Getenv("F5_ADMIN_PASSWORD")

	if username != expectedUsername {
		return errors.New("unknown username")
	}

	if password != expectedPassword {
		return errors.New("bad authentication")
	}

	return nil
}

type LoginRequest struct {
	Username      string `json:"username" validate:"required"`
	Password      string `json:"password" validate:"required"`
	LoginProvider string `json:"loginProvider" validate:"required"`
}

type LoginResponse struct {
	Token Token `json:"token"`
}

type Token struct {
	Token string `json:"token"`
}
