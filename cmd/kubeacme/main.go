package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prep/kubeacme"
)

func getEnv(env, defaultValue string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}

	return defaultValue
}

func getEnvList(env string) []string {
	return strings.FieldsFunc(os.Getenv(env), func(c rune) bool {
		return c == ',' || c == ' '
	})
}

// shutdownFunc calls fn whenever this process gets the signal to shut down.
func shutdownFunc(fn func()) {
	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigC
		fn()
	}()
}

func main() {
	agent, err := kubeacme.New(kubeacme.Config{
		Domains:                   getEnvList("KUBEACME_DOMAINS"),
		EmailAddress:              getEnv("KUBEACME_EMAIL", ""),
		SecretCertName:            getEnv("KUBEACME_CERT_NAME", "ssl-certificate-secret"),
		SecretCertNamespace:       getEnv("KUBEACME_CERT_NAMESPACE", "nginx"),
		SecretAccountKeyName:      getEnv("KUBEACME_ACCOUNT_KEY_NAME", "account-key"),
		SecretAccountKeyNamespace: getEnv("KUBEACME_ACCOUNT_KEY_NAMESPACE", "kubeacme"),
	})
	if err != nil {
		log.Fatalf("Unable to create kubeacme client: %s", err)
	}

	// Set up an HTTP handler.
	server := &http.Server{
		Addr:              getEnv("KUBEACME_ADDR", ":8080"),
		Handler:           newHandler(agent),
		ReadTimeout:       3 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}

	// Clean shutdown.
	shutdownFunc(func() {
		log.Printf("Shutting down service")
		_ = server.Shutdown(context.Background())
	})

	// Spin up the HTTP server.
	log.Printf("Listening on port %s", server.Addr)

	err = server.ListenAndServe()
	switch {
	case errors.Is(err, http.ErrServerClosed):
	case err != nil:
		log.Fatalf("ListenAndServe: %s", err)
	}

	log.Printf("Service shut down")
}
