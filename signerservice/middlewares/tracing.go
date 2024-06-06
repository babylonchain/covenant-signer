package middlewares

import (
	"net/http"

	"github.com/babylonchain/covenant-signer-private/observability/tracing"
)

func TracingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := tracing.AttachTracingIntoContext(r.Context())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
