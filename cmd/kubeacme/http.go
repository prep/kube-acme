package main

import (
	"net/http"

	"github.com/prep/kubeacme"
)

type Handler struct {
	agent  *kubeacme.Agent
	router *http.ServeMux
}

// newHandler returns a new Handler.
func newHandler(agent *kubeacme.Agent) *Handler {
	h := &Handler{agent: agent}

	h.router = http.NewServeMux()
	h.router.HandleFunc("/healthz", h.health)
	h.router.HandleFunc("/renew", h.renew)
	h.router.HandleFunc(kubeacme.ChallengePath, agent.HandleHTTP01Challenge)

	return h
}

// ServeHTTP dispatches the request to the router.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.router.ServeHTTP(w, r)
}

// health returns a 200 OK response to tell k8s that this instance is healthy.
func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// renew handles the renewal of the certificate by requesting a new ACME
// challenge.
func (h *Handler) renew(w http.ResponseWriter, r *http.Request) {
	err := h.agent.Request(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
