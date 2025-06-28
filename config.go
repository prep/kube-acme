package kubeacme

import "errors"

type Config struct {
	Domains      []string
	EmailAddress string

	// SecretCertName and SecretCertNamespace define the name and namespace of
	// the kubernetes secret to store the TLS certificate and private key.
	SecretCertName      string
	SecretCertNamespace string

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
	case c.SecretCertName == "":
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
