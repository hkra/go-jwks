// Package jwks provides a client for fetching RSA signing keys from a JSON
// Web Key Set endpoint.
package jwks

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	defaultRequestTimeout = time.Duration(30)
	defaultcacheTimeout   = time.Duration(600)
)

// Client reads signing keys from a JSON Web Key set endpoint.
type Client struct {
	config      *ClientConfig
	httpClient  *http.Client
	endpointURL string
	expiration  time.Time
	keys        *Keys
	mutex       sync.RWMutex
}

// ClientConfig contains configuration for JWKS client.
type ClientConfig struct {
	disableStrictTLS   bool
	enableDebugLogging bool
	logger             *log.Logger
	cacheTimeout       time.Duration
	requestTimeout     time.Duration
}

// NewConfig creates a new configuration object pre-populated with default values.
func NewConfig() *ClientConfig {
	return &ClientConfig{
		disableStrictTLS: false,
		cacheTimeout:     defaultcacheTimeout,
		requestTimeout:   defaultRequestTimeout,
		logger:           log.New(os.Stderr, "go-jwks: ", log.LstdFlags|log.Lshortfile),
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

// WithDebugLogging enables or disables debug logging. If a logger is not
// specified, the default logger (stderr) will be used.
func (c *ClientConfig) WithDebugLogging(enableDebugLogging bool, logger *log.Logger) *ClientConfig {
	c.enableDebugLogging = enableDebugLogging
	if enableDebugLogging && logger != nil {
		c.logger = logger
	}
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

// NewClient creates a new JWKS client. The client is thread-safe.
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

// GetKeys retrieves the keys from the JWKS endpoint. Cached values will be returned
// if available.
func (c *Client) GetKeys() (keys []Key, err error) {
	// Oh this is all so ugly. There must be a better way :(
	defer func() {
		if rerr := recover(); rerr != nil && c.config.enableDebugLogging {
			c.config.logger.Printf("Recovered from panic [%s].", rerr)
		}
	}()
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if c.keys == nil || time.Now().After(c.expiration) {
		c.mutex.RUnlock()
		if err = c.updateKeys(); err == nil {
			keys, err = c.keys.Keys, nil
		} else if c.config.enableDebugLogging {
			c.config.logger.Println(err)
		}
		c.mutex.RLock()
	}
	return c.keys.Keys, err
}

// GetSigningKey is a convenience function which returns a signing key with
// the specified key ID, or nil if the key doesn't exist in the key set.
func (c *Client) GetSigningKey(kid string) (result *Key, err error) {
	keys, err := c.GetKeys()
	if err == nil {
		for _, key := range keys {
			if key.Kid == kid && key.Use == "sig" {
				result = &key
			}
		}
	}
	return result, err
}

func (c *Client) updateKeys() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Another writer may have updated while we were waiting for the
	// write lock, so check again.
	if time.Now().Before(c.expiration) {
		return nil
	}

	if c.config.enableDebugLogging {
		c.config.logger.Println("Begin fetch key set.")
	}

	resp, err := c.httpClient.Get(c.endpointURL)
	if err != nil {
		return err
	}

	// Always close any non-nil response Body
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Keys request returned non-success status (%d)", resp.StatusCode)
	}

	keys := &Keys{}
	if err := json.NewDecoder(resp.Body).Decode(keys); err != nil {
		return err
	}

	c.keys = keys
	c.expiration = time.Now().Add(c.config.cacheTimeout * time.Second)
	if c.config.enableDebugLogging {
		c.config.logger.Printf("Fetched %d keys. Expires: %v.\n", len(c.keys.Keys), c.expiration)
	}
	return nil
}
