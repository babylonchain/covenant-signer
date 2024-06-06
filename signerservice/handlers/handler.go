package handlers

import (
	"context"
	"net/http"

	m "github.com/babylonchain/covenant-signer-private/observability/metrics"
	s "github.com/babylonchain/covenant-signer-private/signerapp"
)

type Handler struct {
	s *s.SignerApp
	m *m.CovenantSignerMetrics
}

type Result struct {
	Data   interface{}
	Status int
}

type PublicResponse[T any] struct {
	Data T `json:"data"`
}

func NewResult[T any](data T) *Result {
	res := &PublicResponse[T]{Data: data}
	return &Result{Data: res, Status: http.StatusOK}
}

func NewHandler(
	_ context.Context, s *s.SignerApp, m *m.CovenantSignerMetrics,
) (*Handler, error) {
	return &Handler{
		s: s,
		m: m,
	}, nil
}
