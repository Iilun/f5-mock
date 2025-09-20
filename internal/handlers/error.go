package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
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
