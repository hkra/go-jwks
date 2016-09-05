package jwks

import (
	"testing"
	"time"
)

func newConfigSetsDefaults(t *testing.T) {
	config := NewConfig()
	if config.cacheTimeout != time.Duration(30) ||
		config.requestTimeout != time.Duration(30) ||
		config.disableStrictTLS != false {
		t.Fail()
	}
}

func withCacheTimeoutSetsCacheTimeout(t *testing.T) {
	config := NewConfig()
	result := config.WithCacheTimeout(time.Duration(60))
	if config.cacheTimeout != time.Duration(60) {
		t.Fail()
	}
	if config != result {
		t.Fail()
	}
}

func withRequestTimeoutSetsRequestTimeout(t *testing.T) {
	config := NewConfig()
	result := config.WithRequestTimeout(time.Duration(42))
	if config.requestTimeout != time.Duration(42) {
		t.Fail()
	}
	if config != result {
		t.Fail()
	}
}

func withStrictTLSPolicySetsTLSVerifyPolicy(t *testing.T) {
	config := NewConfig()
	result := config.WithStrictTLSPolicy(true)
	if config.disableStrictTLS != true {
		t.Fail()
	}
	if config != result {
		t.Fail()
	}
}
