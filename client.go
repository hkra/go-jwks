// Package jwks provides a client for
package jwks

import (
	"encoding/json"
	"net/http"
	"time"
)

const defaultRequestTimeout = time.Duration(30)

var httpClient *http.Client

func init() {
	httpClient = &http.Client{
		Timeout: defaultRequestTimeout * time.Second,
	}
}

// Client reads signing keys from a JSON Web Key set endpoint.
type Client struct {
	options     *Options
	endpointURL string
}

// Options for JWKS client.
type Options struct {
	// StrictTLS enables or disables strict TLS certificate verification
	// for key requests. This option is enabled by default.
	StrictTLS bool

	// Timeout is the keys request timeout in seconds.
	Timeout time.Duration

	// DebugLogging enables the emission of debug-level log events. By default,
	// all logging is disabled.
	DebugLogging bool

	// ErrorLogging enables the emission of error-level or critical log events.
	// By default, all logging is disabled.
	ErrorLogging bool
}

// Key is a JSON web key returned by the JWKS request.
type Key struct {
	// The "kid" (key ID) parameter is used to match a specific key.
	Kid string `json:"kid"`

	// The "kty" (key type) parameter identifies the cryptographic algorithm
	// family used with the key, such as "RSA" or "EC".  "kty" values should
	// either be registered in the IANA "JSON Web Key Types" registry
	// established by or be a value that contains a Collision-resistant name.
	// The "kty" value is a case-sensitive string.
	Kty string `json:"kty"`

	// The "key_ops" (key operations) parameter identifies the operation(s)
	// for which the key is intended to be used.  The "key_ops" parameter is
	// intended for use cases in which public, private, or symmetric keys
	// may be present.
	KeyOps []string `json:"key_ops"`

	// The "alg" (algorithm) parameter identifies the algorithm intended for
	// use with the key.  The values used should either be registered in the
	// IANA "JSON Web Signature and Encryption Algorithms" registry
	// established by JWA or be a value that contains a Collision-
	// Resistant Name.  The "alg" value is a case-sensitive ASCII string.
	Alg string `json:"alg"`

	// The "use" (public key use) parameter identifies the intended use of
	// the public key. The "use" parameter is employed to indicate whether
	// a public key is used for encrypting data or verifying the signature
	// on data.
	Use string `json:"use"`

	// The "x5c" (X.509 certificate chain) parameter contains a chain of one
	// or more PKIX certificates.  The certificate chain is represented as a
	// JSON array of certificate value strings.  Each string in the array is
	// a base64-encoded (not base64url-encoded) DER [ITU.X690.1994] PKIX
	// certificate value.
	X5c []string `json:"x5c"`

	// The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a
	// base64url-encoded SHA-1 thumbprint of the DER encoding of an X.509
	// certificate.
	X5t string `json:"x5t"`

	// N is the RSA key value modulus.
	N string `json:"n"`

	// E is the RSA key value public exponent.
	E string `json:"e"`
}

// Keys represents a set of JSON web keys.
type Keys struct {
	// Keys is an array of JSON web keys.
	Keys []Key `json:"keys"`
}

// SetRequestTimeout sets the timeout for requests to the JWKS endpoint.
// The timeout should be a unitless duration, which will be interpreted
// by SetRequestTimeout in seconds.
func SetRequestTimeout(timeout time.Duration) {
	httpClient.Timeout = timeout * time.Second
}

// New creates a new JWKS client.
func New(jwksEndpoint string, options *Options) *Client {
	return &Client{
		options:     options,
		endpointURL: jwksEndpoint,
	}
}

// GetKeys retrieves the keys from the JWKS respendpoint.
func (c *Client) GetKeys() error {
	resp, err := httpClient.Get(c.endpointURL)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	keys := Keys{}
	if err := json.NewDecoder(resp.Body).Decode(keys); err != nil {
		return err
	}

	return nil
}
