package jwks

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewConfigSetsDefaults(t *testing.T) {
	config := NewConfig()
	assert(t, config.cacheTimeout == defaultcacheTimeout)
	assert(t, config.requestTimeout == defaultRequestTimeout)
	assert(t, config.disableStrictTLS == false)
}

func TestWithCacheTimeoutSetsCacheTimeout(t *testing.T) {
	config := NewConfig()
	result := config.WithCacheTimeout(time.Duration(60))
	assert(t, config.cacheTimeout == time.Duration(60))
	assert(t, config == result)
}

func TestWithRequestTimeoutSetsRequestTimeout(t *testing.T) {
	config := NewConfig()
	result := config.WithRequestTimeout(time.Duration(42))
	assert(t, config.requestTimeout == time.Duration(42))
	assert(t, config == result)
}

func TestWithStrictTLSPolicySetsTLSVerifyPolicy(t *testing.T) {
	config := NewConfig()
	result := config.WithStrictTLSPolicy(true)
	assert(t, config.disableStrictTLS == true)
	assert(t, config == result)
}

func TestWithDebugLoggingCustomLogger(t *testing.T) {
	config := NewConfig()
	buf := &bytes.Buffer{}
	logger := log.New(buf, "custom: ", log.LstdFlags)
	result := config.WithDebugLogging(true, logger)

	assert(t, config.enableDebugLogging == true)
	assert(t, config.logger == logger)
	assert(t, config == result)

	logger.Println("custom logger")
	loggedMsg := buf.String()
	assert(t, strings.HasPrefix(loggedMsg, "custom: "))
	assert(t, strings.Contains(loggedMsg, "custom logger"))
}

func TestWithDebugLoggingStandardLogger(t *testing.T) {
	oldErr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	config := NewConfig()
	result := config.WithDebugLogging(true, nil)

	assert(t, config.enableDebugLogging == true)
	assert(t, config == result)

	config.logger.Println("logged to stderr")

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	w.Close()
	os.Stderr = oldErr
	loggedMsg := <-outC

	assert(t, strings.HasPrefix(loggedMsg, "go-jwks: "))
	assert(t, strings.Contains(loggedMsg, "logged to stderr"))
}

func TestDefaultClientConfiguration(t *testing.T) {
	client := NewClient("http://127.0.0.1", nil)
	assert(t, client.config.cacheTimeout == defaultcacheTimeout)
	assert(t, client.config.requestTimeout == defaultRequestTimeout)
	assert(t, client.config.disableStrictTLS == false)
	assert(t, client.config.enableDebugLogging == false)
}

type mockErrorTransport struct{}
type mockSuccessTransport struct{}
type mockMalformedTransport struct{}

func (t *mockErrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response := &http.Response{
		Header:     make(http.Header),
		Request:    req,
		StatusCode: http.StatusInternalServerError,
	}
	return response, nil
}

func (t *mockSuccessTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response := &http.Response{
		Header:     make(http.Header),
		Request:    req,
		StatusCode: http.StatusOK,
	}
	responseBody := `{"keys":[{"alg":"RS256","kty":"RSA","use":"sig","x5c":["D4dtuk"],"n":"VKOoRQ","e":"AQAB","kid":"GREY2MQ","x5t":"GREY2MQ"}]}`
	response.Body = ioutil.NopCloser(strings.NewReader(responseBody))
	return response, nil
}

func (t *mockMalformedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response := &http.Response{
		Header:     make(http.Header),
		Request:    req,
		StatusCode: http.StatusOK,
	}
	response.Body = ioutil.NopCloser(strings.NewReader(`{"keys":[{"blah":"jjj"}}`))
	return response, nil
}

func setupMockedHTTPTest(resultType string) *Client {
	client := http.DefaultClient
	switch true {
	case resultType == "error":
		client.Transport = &mockErrorTransport{}
	case resultType == "malformed":
		client.Transport = &mockMalformedTransport{}
	case resultType == "success":
		fallthrough
	default:
		client.Transport = &mockSuccessTransport{}
	}

	config := NewConfig()
	JWKSClient := NewClient("http://ilikepie.com", config)
	JWKSClient.httpClient = client
	return JWKSClient
}

func TestErroredHttpRequest(t *testing.T) {
	client := setupMockedHTTPTest("error")
	_, err := client.GetKeys()
	assert(t, err != nil)
}

func TestErroredHttpRequestDebugLogging(t *testing.T) {
	client := setupMockedHTTPTest("error")
	buf := &bytes.Buffer{}
	logger := log.New(buf, "custom: ", log.LstdFlags)
	client.config.WithDebugLogging(true, logger)

	_, err := client.GetKeys()
	assert(t, err != nil)

	loggedMsg := buf.String()
	assert(t, strings.Contains(loggedMsg, "Begin fetch key set"))
	assert(t, strings.Contains(loggedMsg, "Keys request returned non-success status (500)"))
	assert(t, strings.Contains(loggedMsg, "Recovered from panic"))
}

func TestSuccessHttpRequestDebugLogging(t *testing.T) {
	client := setupMockedHTTPTest("success")
	buf := &bytes.Buffer{}
	logger := log.New(buf, "custom: ", log.LstdFlags)
	client.config.WithDebugLogging(true, logger)

	_, err := client.GetKeys()

	loggedMsg := buf.String()
	assert(t, err == nil)
	assert(t, strings.Contains(loggedMsg, "Fetched 1 keys"))
}

func TestSuccessHttpRequestNoKey(t *testing.T) {
	client := setupMockedHTTPTest("success")
	assert(t, client.expiration.IsZero())
	keys, err := client.GetKeys()

	assert(t, err == nil)
	assert(t, len(keys) == 1)

	key := keys[0]
	assert(t, key.Alg == "RS256")
	assert(t, key.Kid == "GREY2MQ")
	assert(t, key.Kty == "RSA")
	assert(t, key.Use == "sig")
	assert(t, key.X5t == "GREY2MQ")
	assert(t, len(key.X5c) == 1)
	assert(t, key.X5c[0] == "D4dtuk")
	assert(t, key.E == "AQAB")
	assert(t, key.N == "VKOoRQ")
	assert(t, !client.expiration.IsZero())
}

func TestMalformedHttpRequest(t *testing.T) {
	client := setupMockedHTTPTest("malformed")
	keys, err := client.GetKeys()
	assert(t, err != nil)
	assert(t, keys == nil)
}

func TestGetSigningKeyForExistingKey(t *testing.T) {
	client := setupMockedHTTPTest("success")
	key, err := client.GetSigningKey("GREY2MQ")
	assert(t, err == nil)
	assert(t, key != nil)
}

func TestGetSigningKeyForNonExistingKey(t *testing.T) {
	client := setupMockedHTTPTest("success")
	key, err := client.GetSigningKey("non-key-id")
	assert(t, err == nil)
	assert(t, key == nil)
}

func TestExpirationCheckBeforeUpdate(t *testing.T) {
	client := NewClient("endpoint", nil)
	client.expiration = time.Now().AddDate(1, 0, 0)
	err := client.updateKeys()
	assert(t, err == nil)
}

func assert(t *testing.T, condition bool) {
	if !condition {
		t.Fail()
	}
}
