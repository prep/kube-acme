// Package kubeacme provides an ACME client that stores certificates and account keys in Kubernetes secrets.
package kubeacme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// The challenge prefix and path are used to serve the HTTP-01 challenge response.
const (
	ChallengePrefix = "/.well-known/acme-challenge/"
	ChallengePath   = ChallengePrefix + "{token}"
)

// Agent is an ACME client that can be hooked in quite easily into an net/http
// server.
type Agent struct {
	client    *kubernetes.Clientset
	config    Config
	challenge map[string]string
	mu        sync.Mutex
}

// New returns a new Agent.
func New(config Config) (*Agent, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}

	k8scfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(k8scfg)
	if err != nil {
		return nil, err
	}

	return &Agent{
		client:    client,
		config:    config,
		challenge: make(map[string]string),
	}, nil
}

// storeSecret stores a Kubernetes secret.
func (a *Agent) storeSecret(ctx context.Context, secret *corev1.Secret) error {
	secrets := a.client.CoreV1().Secrets(secret.ObjectMeta.Namespace)

	_, err :=
		secrets.Get(ctx, secret.Name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		_, err = secrets.Create(ctx, secret, metav1.CreateOptions{})
	case err != nil:
	default:
		_, err = secrets.Update(ctx, secret, metav1.UpdateOptions{})
	}

	attrs := slog.Group("k8s",
		slog.String("namespace", secret.ObjectMeta.Namespace),
		slog.String("name", secret.ObjectMeta.Name),
	)

	if err != nil {
		slog.ErrorContext(ctx, "Unable to store secret", attrs)
		return err
	}

	slog.InfoContext(ctx, "Secret stored", attrs)
	return nil
}

const timeFormat = "20060102"

// storeCert stores the certificate and private key in a Kubernetes secret.
func (a *Agent) storeCert(ctx context.Context, certPEM, keyPEM []byte) (string, error) {
	name := a.config.SecretCertNamePrefix + "-" + time.Now().Format(timeFormat)

	secret := &corev1.Secret{
		Type: corev1.SecretTypeTLS,
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: a.config.SecretCertNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}

	if err := a.storeSecret(ctx, secret); err != nil {
		return "", err
	}

	return name, nil
}

const ecsdsaPrivateKey = "ecdsa.key"

// storeAccountKey stores an ACME account key.
func (a *Agent) storeAccountKey(ctx context.Context, key *ecdsa.PrivateKey) error {
	data, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	secret := &corev1.Secret{
		Type: corev1.SecretTypeOpaque,
		ObjectMeta: metav1.ObjectMeta{
			Name:      a.config.SecretAccountKeyName,
			Namespace: a.config.SecretAccountKeyNamespace,
		},
		Data: map[string][]byte{
			ecsdsaPrivateKey: data,
		},
	}

	return a.storeSecret(ctx, secret)
}

var errAccountKeyNotFound = errors.New("account key not found")

// getAccountKey retrieves the ACME account key.
func (a *Agent) getAccountKey(ctx context.Context) (*ecdsa.PrivateKey, error) {
	secrets := a.client.CoreV1().Secrets(a.config.SecretAccountKeyNamespace)

	// Get the secret containing the account key.
	secret, err := secrets.Get(ctx, a.config.SecretAccountKeyName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return nil, errAccountKeyNotFound
	case err != nil:
		return nil, err
	}

	// Verify that the private key is present in the secret.
	data, ok := secret.Data[ecsdsaPrivateKey]
	if !ok {
		return nil, fmt.Errorf("%s: missing account key secret", a.config.SecretAccountKeyName)
	}

	// Parse the private key from the secret data.
	key, err := x509.ParseECPrivateKey(data)
	if err != nil {
		return nil, err
	}

	return key, nil
}

const annotationKey = "service.beta.kubernetes.io/oci-load-balancer-tls-secret"

func (a *Agent) updateService(ctx context.Context, value string) error {
	// Construct the JSON payload of the patch.
	patch, err := json.Marshal(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				annotationKey: value,
			},
		},
	})
	if err != nil {
		return err
	}

	slog.InfoContext(ctx, "Updating service annotation",
		slog.String("key", annotationKey),
		slog.String("value", value),
		slog.Group("k8s",
			slog.String("name", a.config.ServiceName),
			slog.String("namespace", a.config.ServiceNamespace),
		))

	// Patch the service with the new annotation.
	_, err = a.client.CoreV1().Services(a.config.ServiceNamespace).
		Patch(ctx, a.config.ServiceName, types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

// HandleHTTP01Challenge serves the ACME HTTP-01 challenge response.
func (a *Agent) HandleHTTP01Challenge(w http.ResponseWriter, r *http.Request) {
	// Extract the token.
	//
	// Use strings.TrimPrefix instead of r.PathValue because this approach makes
	// it compatible when the implementer doesn't use a router that supports path
	// variables.
	token := strings.TrimPrefix(r.URL.Path, ChallengePrefix)

	a.mu.Lock()
	resp, ok := a.challenge[token]
	a.mu.Unlock()

	if !ok {
		slog.ErrorContext(r.Context(), "ACME challenge NOT found")
		http.Error(w, "Invalid challenge", http.StatusNotFound)
		return
	}

	slog.InfoContext(r.Context(), "ACME challenge found")

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(resp))
}

// Request an ACME HTTP-01 challenge.
func (a *Agent) Request(ctx context.Context) (string, error) {
	var register bool

	// Fetch the account key from the Kubernetes secret.
	accountKey, err := a.getAccountKey(ctx)
	switch {
	// If no account key was found, generate a new one.
	case errors.Is(err, errAccountKeyNotFound):
		accountKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", err
		}

		// Store the account key in a Kubernetes secret.
		if err = a.storeAccountKey(ctx, accountKey); err != nil {
			return "", fmt.Errorf("storeAccountKey: %w", err)
		}

		// Set the register flag to true, so we can register the account with ACME
		// as the first operation that is done after creating the ACME client.
		register = true

	case err != nil:
		return "", fmt.Errorf("getAccountKey: %w", err)
	}

	// Create the ACME client and account.
	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: acme.LetsEncryptURL,
	}

	// Register the new ACME account.
	if register {
		account := &acme.Account{
			Contact: []string{
				"mailto:" + a.config.EmailAddress,
			},
		}

		// Register the account with the ACME server.
		_, err = client.Register(ctx, account, acme.AcceptTOS)
		switch {
		case errors.Is(err, acme.ErrAccountAlreadyExists):
		case err != nil:
			return "", fmt.Errorf("acme.Register: %w", err)
		}
	}

	// Create an order for the domains.
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(a.config.Domains...))
	if err != nil {
		return "", fmt.Errorf("acme.AuthorizeOrder: %w", err)
	}

	// Process all challenges for all authorizations.
	var challenges []*acme.Challenge
	var authzURLs []string
	for _, url := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, url)
		if err != nil {
			return "", fmt.Errorf("acme.GetAuthorization: %w", err)
		}

		// Find the HTTP-01 challenge for this authorization
		var challenge *acme.Challenge
		for _, chal := range authz.Challenges {
			if chal.Type == "http-01" {
				challenge = chal
				break
			}
		}

		if challenge == nil {
			return "", fmt.Errorf("no http-01 challenge found for authorization %s", url)
		}

		challenges = append(challenges, challenge)
		authzURLs = append(authzURLs, url)
	}

	if len(challenges) == 0 {
		return "", fmt.Errorf("no http-01 challenges found")
	}

	// Prepare all challenge responses.
	a.mu.Lock()
	for _, challenge := range challenges {
		keyAuth, err := client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			a.mu.Unlock()
			return "", fmt.Errorf("acme.HTTP01ChallengeResponse: %w", err)
		}

		a.challenge[challenge.Token] = keyAuth
	}
	a.mu.Unlock()

	// Delete all challenge responses when done.
	defer func() {
		a.mu.Lock()
		defer a.mu.Unlock()

		for _, challenge := range challenges {
			delete(a.challenge, challenge.Token)
		}
	}()

	// Accept all challenges
	for _, challenge := range challenges {
		_, err = client.Accept(ctx, challenge)
		if err != nil {
			return "", fmt.Errorf("acme.Accept: %s: %w", challenge.Token, err)
		}
	}

	// Wait for each authorization to be validated.
	for _, url := range authzURLs {
		_, err = client.WaitAuthorization(ctx, url)
		if err != nil {
			return "", fmt.Errorf("acme.WaitAuthorization: %s: %w", url, err)
		}
	}

	// Wait for the order to be ready.
	_, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return "", fmt.Errorf("acme.WaitOrder: %w", err)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("ecdsa.GenerateKey: %w", err)
	}

	// Create a certificate request.
	certReq := &x509.CertificateRequest{
		DNSNames:           a.config.Domains,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, certReq, privateKey)
	if err != nil {
		return "", fmt.Errorf("x509.CreateCertificateRequest: %w", err)
	}

	// Parse the CSR to check for errors.
	_, err = x509.ParseCertificateRequest(csr)
	if err != nil {
		return "", fmt.Errorf("x509.ParseCertificateRequest: %w", err)
	}

	// Submit the CSR.
	ders, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return "", fmt.Errorf("acme.CreateOrderCert: %w", err)
	}

	// Create the certificate PEM. Include the entire chain.
	var certPEM strings.Builder
	for _, der := range ders {
		err = pem.Encode(&certPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		})
		if err != nil {
			return "", fmt.Errorf("pem.Encode: %w", err)
		}
	}

	// Create the private key PEM.
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("x509.MarshalECPrivateKey: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Store the certificate and private key in a Kubernetes secret.
	name, err := a.storeCert(ctx, []byte(certPEM.String()), keyPEM)
	if err != nil {
		return "", fmt.Errorf("storeCert: %w", err)
	}

	// Update the service with a reference to the new TLS certificate secret.
	if err = a.updateService(ctx, name); err != nil {
		return "", fmt.Errorf("updateService: %w", err)
	}

	return name, nil
}
