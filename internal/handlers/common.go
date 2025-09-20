package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/iilun/f5-mock/pkg/cache"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type F5Error struct {
	Message string `json:"message"`
}

func f5Error(w http.ResponseWriter, status int, message string, args ...any) {
	formattedMsg := fmt.Sprintf(message, args...)
	log.Println("ERROR: " + formattedMsg)

	err := F5Error{Message: formattedMsg}
	bytes, _ := json.Marshal(err)
	w.WriteHeader(status)
	w.Write(bytes)
}

func enforceContentTypeMiddleWare(ct string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := checkContentType(r, ct)
		if err != nil {
			f5Error(w, http.StatusUnsupportedMediaType, err.Error())
			return
		}

		next(w, r)
	}
}

func enforceContentTypeIControlMiddleWare(ct string, next IControlHandlerFunc) IControlHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, version int) {
		err := checkContentType(r, ct)
		if err != nil {
			f5Error(w, http.StatusUnsupportedMediaType, err.Error())
			return
		}

		next(w, r, version)
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
			f5Error(w, http.StatusUnauthorized, err.Error())
			return
		}

		next(w, r)
	}
}

func authenticatedIControlRequestMiddleware(next IControlHandlerFunc) IControlHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, version int) {
		err := globalAuthCheck(r)
		if err != nil {
			f5Error(w, http.StatusUnauthorized, err.Error())
			return
		}
		next(w, r, version)
	}
}

func iControlMiddleWare(next IControlHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(fmt.Sprintf("DEBUG: Got request %s for %s", r.Method, r.URL.String()))
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
			f5Error(w, http.StatusBadRequest, "invalid version")
			return
		}

		next(w, r, majorInt)
	}
}
