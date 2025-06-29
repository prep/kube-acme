package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prep/kubeacme"
)

var (
	Revision   string = "unknown"
	CommitHash string = "unknown"
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

func signalHandler(fn func(os.Signal)) {
	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)

	go func() {
		for {
			fn(<-sigC)
		}
	}()
}

func main() {
	ctx := context.Background()

	// Set up logging.
	slog.SetDefault(newLogger(
		slog.Group("app",
			slog.String("name", "kubeacme"),
			slog.String("revision", Revision),
			slog.String("commit", CommitHash),
		),
	))

	// Set up the kubeacme agent, which will handle the ACME challenges and
	// store the TLS certificate in a Kubernetes secret.
	agent, err := kubeacme.New(kubeacme.Config{
		Domains:                   getEnvList("KUBEACME_DOMAINS"),
		EmailAddress:              getEnv("KUBEACME_EMAIL", ""),
		SecretCertName:            getEnv("KUBEACME_CERT_NAME", "ssl-certificate-secret"),
		SecretCertNamespace:       getEnv("KUBEACME_CERT_NAMESPACE", "nginx"),
		SecretAccountKeyName:      getEnv("KUBEACME_ACCOUNT_KEY_NAME", "account-key"),
		SecretAccountKeyNamespace: getEnv("KUBEACME_ACCOUNT_KEY_NAMESPACE", "kubeacme"),
	})
	if err != nil {
		slog.ErrorContext(ctx, "Unable to create kubeacme agent", "error", err)
		os.Exit(1)
	}

	// Set up an HTTP handler.
	server := &http.Server{
		Addr:              getEnv("KUBEACME_ADDR", ":8080"),
		Handler:           newHandler(agent),
		ReadTimeout:       3 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}

	// Handle signals.
	signalHandler(func(sig os.Signal) {
		switch sig {
		// Handle a clean shutdown.
		case syscall.SIGINT, syscall.SIGTERM:
			slog.InfoContext(ctx, "Shutting down service")
			_ = server.Shutdown(ctx)

		// Update the certificate.
		case syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2:
			slog.InfoContext(ctx, "Requesting certificate update")

			if err := agent.Request(ctx); err != nil {
				slog.ErrorContext(ctx, "Unable to request certificate update", "error", err)
			} else {
				slog.InfoContext(ctx, "Certificate update finished")
			}
		}
	})

	// Spin up the HTTP server.
	slog.InfoContext(ctx, "Starting service", "port", server.Addr)

	err = server.ListenAndServe()
	switch {
	case errors.Is(err, http.ErrServerClosed):
	case err != nil:
		slog.ErrorContext(ctx, "Unable to http.ListenAndServe", "error", err)
		os.Exit(1)
	}

	slog.InfoContext(ctx, "Stopping service")
}
