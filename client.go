// Package jwks provides a client for
package jwks

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"time"
)

const (
	defaultRequestTimeout = time.Duration(30)
	defaultcacheTimeout   = time.Duration(600)
)

var httpClient *http.Client

// Client reads signing keys from a JSON Web Key set endpoint.
type Client struct {
	config      *ClientConfig
	httpClient  *http.Client
	endpointURL string
}

// ClientConfig contains configuration for JWKS client.
type ClientConfig struct {
	disableStrictTLS bool
	cacheTimeout     time.Duration
	requestTimeout   time.Duration
}

// NewConfig creates a new configuration object pre-populated with default values.
func NewConfig() *ClientConfig {
	return &ClientConfig{
		disableStrictTLS: false,
		cacheTimeout:     defaultcacheTimeout,
		requestTimeout:   defaultRequestTimeout,
	}
}

// WithCacheTimeout sets the cache TTL for fetched keys.
func (c *ClientConfig) WithCacheTimeout(timeout time.Duration) *ClientConfig {
	c.cacheTimeout = timeout
	return c
}

// WithRequestTimeout sets the request timeout for key requests.
func (c *ClientConfig) WithRequestTimeout(timeout time.Duration) *ClientConfig {
	c.requestTimeout = timeout
	return c
}

// WithStrictTLSPolicy enables or disables TSL certificate verification.
func (c *ClientConfig) WithStrictTLSPolicy(verificationDisabled bool) *ClientConfig {
	c.disableStrictTLS = verificationDisabled
	return c
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

	// TODO: add other fields
}

// Keys represents a set of JSON web keys.
type Keys struct {
	// Keys is an array of JSON web keys.
	Keys []Key `json:"keys"`
}

// NewClient creates a new JWKS client.
func NewClient(jwksEndpoint string, config *ClientConfig) *Client {
	if config == nil {
		config = NewConfig()
	}

	client := &Client{
		config:      config,
		endpointURL: jwksEndpoint,
		httpClient: &http.Client{
			Timeout: defaultRequestTimeout * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: config.disableStrictTLS},
			},
		},
	}

	return client
}

// GetKeys retrieves the keys from the JWKS respendpoint.
func (c *Client) GetKeys() (*Keys, error) {
	resp, err := httpClient.Get(c.endpointURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	keys := &Keys{}
	if err := json.NewDecoder(resp.Body).Decode(keys); err != nil {
		return nil, err
	}

	return keys, nil
}
