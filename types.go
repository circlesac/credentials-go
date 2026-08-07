package credentials

import (
	"context"
	"net/http"
	"time"
)

// Kind identifies the Bearer value syntax without authenticating it.
type Kind string

const (
	KindJWT    Kind = "jwt"
	KindAPIKey Kind = "api_key"
)

// SourceType identifies the winning provider category.
type SourceType string

const (
	SourceExplicit    SourceType = "explicit"
	SourceEnvironment SourceType = "environment"
	SourceProfile     SourceType = "profile"
)

// Source contains only non-secret diagnostic metadata.
type Source struct {
	Type    SourceType `json:"type"`
	Profile string     `json:"profile,omitempty"`
}

// Credential is a resolved Circles Bearer credential.
type Credential struct {
	Value     string
	Kind      Kind
	ExpiresAt *time.Time
	Source    Source
}

// CredentialProvider resolves a credential with cancellation support.
type CredentialProvider interface {
	Resolve(context.Context) (Credential, error)
}

// ProfileConfig contains non-secret endpoint and default-context settings.
type ProfileConfig struct {
	APIURL  string
	AuthURL string
	Org     string
}

// StoredProfile is the non-secret portion of a named profile.
type StoredProfile struct {
	Name   string
	Config ProfileConfig
}

// ProfileCredentials replaces one profile's credential form.
type ProfileCredentials struct {
	AccessToken  string
	RefreshToken string
	APIKey       string
}

// ProfileUpdate updates either or both shared profile files.
type ProfileUpdate struct {
	Config      *ProfileConfig
	Credentials *ProfileCredentials
}

// FilePaths are the canonical and compatibility paths used by a Provider.
type FilePaths struct {
	ConfigFile            string
	CredentialsFile       string
	LegacyConfigFile      string
	LegacyCredentialsFile string
	LegacyJSONFile        string
}

type httpClient interface {
	Do(*http.Request) (*http.Response, error)
}

type providerOptions struct {
	explicitCredential *string
	explicitProvider   CredentialProvider
	profile            *string
	env                map[string]string
	homeDir            string
	configFile         *string
	credentialsFile    *string
	httpClient         httpClient
	now                func() time.Time
	clientID           string
	lockTimeout        time.Duration
}

// Option configures a Provider.
type Option func(*providerOptions)

// WithCredential supplies the highest-precedence in-memory Bearer value.
func WithCredential(value string) Option {
	return func(options *providerOptions) {
		options.explicitCredential = &value
		options.explicitProvider = nil
	}
}

// WithCredentialProvider supplies the highest-precedence credential provider.
func WithCredentialProvider(provider CredentialProvider) Option {
	return func(options *providerOptions) {
		options.explicitProvider = provider
		options.explicitCredential = nil
	}
}

// WithProfile selects a named profile explicitly.
func WithProfile(profile string) Option {
	return func(options *providerOptions) {
		options.profile = &profile
	}
}

// WithEnvironment replaces the process environment, primarily for embedding and tests.
func WithEnvironment(environment map[string]string) Option {
	return func(options *providerOptions) {
		options.env = make(map[string]string, len(environment))
		for key, value := range environment {
			options.env[key] = value
		}
	}
}

// WithHomeDir replaces the operating-system home directory.
func WithHomeDir(home string) Option {
	return func(options *providerOptions) {
		options.homeDir = home
	}
}

// WithConfigFile replaces the shared config path.
func WithConfigFile(path string) Option {
	return func(options *providerOptions) {
		options.configFile = &path
	}
}

// WithCredentialsFile replaces the shared credentials path.
func WithCredentialsFile(path string) Option {
	return func(options *providerOptions) {
		options.credentialsFile = &path
	}
}

// WithHTTPClient replaces the OAuth refresh HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(options *providerOptions) {
		options.httpClient = client
	}
}

// WithNow replaces the clock.
func WithNow(now func() time.Time) Option {
	return func(options *providerOptions) {
		options.now = now
	}
}

// WithClientID replaces the OAuth public client identifier.
func WithClientID(clientID string) Option {
	return func(options *providerOptions) {
		options.clientID = clientID
	}
}

// WithLockTimeout replaces the cross-process lock wait timeout.
func WithLockTimeout(timeout time.Duration) Option {
	return func(options *providerOptions) {
		options.lockTimeout = timeout
	}
}
