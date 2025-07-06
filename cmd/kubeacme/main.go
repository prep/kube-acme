package main

import (
	"context"
	"errors"
	"flag"
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
	flag.Parse()

	// Set up logging.
	slog.SetDefault(newLogger(
		slog.Group("app",
			slog.String("name", "kube-acme"),
			slog.String("revision", Revision),
			slog.String("commit", CommitHash),
		),
	))

	ctx := context.Background()

	// If the first argument is "request", we send a SIGHUP to the process
	// to trigger a certificate refresh.
	if flag.NArg() != 0 && flag.Arg(0) == "request" {
		if err := syscall.Kill(1, syscall.SIGHUP); err != nil {
			slog.ErrorContext(ctx, "Unable to signal for a request", "error", err)
		}

		return
	}

	config := kubeacme.Config{
		Domains:      getEnvList("KUBEACME_DOMAINS"),
		EmailAddress: getEnv("KUBEACME_EMAIL", ""),

		SecretCertNamePrefix: getEnv("KUBEACME_CERT_NAMEPREFIX", "ssl-cert"),
		SecretCertNamespace:  getEnv("KUBEACME_CERT_NAMESPACE", "nginx"),
		ServiceName:          getEnv("KUBEACME_SERVICE_NAME", "nginx-service"),
		ServiceNamespace:     getEnv("KUBEACME_SERVICE_NAMESPACE", "nginx"),

		SecretAccountKeyName:      getEnv("KUBEACME_ACCOUNT_KEY_NAME", "account-key"),
		SecretAccountKeyNamespace: getEnv("KUBEACME_ACCOUNT_KEY_NAMESPACE", "kube-acme"),
	}

	// Set up the kubeacme agent, which will handle the ACME challenges and
	// store the TLS certificate in a Kubernetes secret.
	agent, err := kubeacme.New(config)
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
			slog.InfoContext(ctx, "Stopping service")
			_ = server.Shutdown(ctx)

		// Update the certificate.
		case syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2:
			slog.InfoContext(ctx, "Requesting certificate update")

			name, err := agent.Request(ctx)
			if err != nil {
				slog.ErrorContext(ctx, "Unable to request certificate update", "error", err)
				return
			}

			slog.InfoContext(ctx, "Certificate update finished",
				slog.Group("k8s",
					slog.String("name", name),
					slog.String("namespace", config.SecretCertNamespace),
				))
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
}
