package jwks

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewConfigSetsDefaults(t *testing.T) {
	config := NewConfig()
	if config.cacheTimeout != time.Duration(600) ||
		config.requestTimeout != time.Duration(30) ||
		config.disableStrictTLS != false {
		t.Fail()
	}
}

func TestWithCacheTimeoutSetsCacheTimeout(t *testing.T) {
	config := NewConfig()
	result := config.WithCacheTimeout(time.Duration(60))
	if config.cacheTimeout != time.Duration(60) {
		t.Fail()
	}
	if config != result {
		t.Fail()
	}
}

func TestWithRequestTimeoutSetsRequestTimeout(t *testing.T) {
	config := NewConfig()
	result := config.WithRequestTimeout(time.Duration(42))
	if config.requestTimeout != time.Duration(42) {
		t.Fail()
	}
	if config != result {
		t.Fail()
	}
}

func TestWithStrictTLSPolicySetsTLSVerifyPolicy(t *testing.T) {
	config := NewConfig()
	result := config.WithStrictTLSPolicy(true)
	if config.disableStrictTLS != true {
		t.Fail()
	}
	if config != result {
		t.Fail()
	}
}

func TestWithDebugLoggingCustomLogger(t *testing.T) {
	config := NewConfig()
	buf := &bytes.Buffer{}
	logger := log.New(buf, "custom: ", log.LstdFlags)
	result := config.WithDebugLogging(true, logger)

	if config.enableDebugLogging != true || config.logger != logger || config != result {
		t.Fail()
	}

	logger.Println("custom logger")
	loggedMsg := buf.String()
	if !strings.HasPrefix(loggedMsg, "custom: ") || !strings.Contains(loggedMsg, "custom logger") {
		t.Fail()
	}
}

func TestWithDebugLoggingStandardLogger(t *testing.T) {
	oldErr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	config := NewConfig()
	result := config.WithDebugLogging(true, nil)

	if config.enableDebugLogging != true || config != result {
		t.Fail()
	}

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

	if !strings.HasPrefix(loggedMsg, "go-jwks: ") || !strings.Contains(loggedMsg, "logged to stderr") {
		t.Fail()
	}
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
	return response, nil
}

func (t *mockMalformedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response := &http.Response{
		Header:     make(http.Header),
		Request:    req,
		StatusCode: http.StatusOK,
	}
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
	if err == nil {
		t.Fail()
	}
}
