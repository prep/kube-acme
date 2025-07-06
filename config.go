package kubeacme

import "errors"

type Config struct {
	// Domains is a list of domains for which to obtain TLS certificates.
	Domains []string

	// EmailAddress is the email address to use for ACME account registration.
	EmailAddress string

	// ServiceName and ServiceNamespace refer to the k8s service whose annotations
	// need updating after a new certificate secret has been stored.
	//
	// If one of these is empty, the service will not be updated.
	ServiceName      string
	ServiceNamespace string

	// SecretCertNamePrefix and SecretCertNamespace define the name prefix and
	// namespace of the kubernetes secret to store the TLS certificate and
	// private key.
	SecretCertNamePrefix string
	SecretCertNamespace  string

	// SecretAccountKeyName and SecretAccountKeyNamespace define the name and
	// namespace of the kubernetes secret where the ACME account key is stored.
	SecretAccountKeyName      string
	SecretAccountKeyNamespace string
}

func (c Config) validate() error {
	switch {
	case len(c.Domains) == 0:
		return errors.New("no domains specified")
	case c.EmailAddress == "":
		return errors.New("no email address specified")
	case c.SecretCertNamePrefix == "":
		return errors.New("no secret cert name specified")
	case c.SecretCertNamespace == "":
		return errors.New("no secret cert namespace specified")
	case c.SecretAccountKeyName == "":
		return errors.New("no secret account key name specified")
	case c.SecretAccountKeyNamespace == "":
		return errors.New("no secret account key namespace specified")
	}

	return nil
}
