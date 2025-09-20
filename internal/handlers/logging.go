package handlers

import (
	"context"
	"github.com/google/uuid"
	"github.com/iilun/f5-mock/internal/log"
	"net/http"
)

type loggerCtxKey struct{}

func loggingMiddleware(logger log.Logger, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestId := uuid.New()

		newLogger := logger.With(
			log.ContextRequestId, requestId,
			"url", r.URL.String(),
			"method", r.Method,
		)

		ctx := context.WithValue(r.Context(), loggerCtxKey{}, newLogger)

		next(w, r.WithContext(ctx))
	}
}

func loggerFromRequest(r *http.Request) log.Logger {
	if l, ok := r.Context().Value(loggerCtxKey{}).(log.Logger); ok {
		return l
	}
	return log.Default
}
