package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// Provider resolves and manages Circles shared credentials.
type Provider struct {
	options providerOptions
	store   *profileStore
	paths   FilePaths
}

// New creates a shared credential provider.
func New(configure ...Option) (*Provider, error) {
	options := providerOptions{
		httpClient:  http.DefaultClient,
		now:         time.Now,
		clientID:    "circles-api",
		lockTimeout: 10 * time.Second,
	}
	for _, configureOption := range configure {
		configureOption(&options)
	}
	if options.httpClient == nil {
		return nil, credentialError(ErrInvalidCredential, "OAuth HTTP client must not be nil.")
	}
	if options.now == nil {
		return nil, credentialError(ErrInvalidCredential, "Credential clock must not be nil.")
	}
	if options.clientID == "" {
		return nil, credentialError(ErrInvalidCredential, "OAuth client ID must not be empty.")
	}
	if options.lockTimeout <= 0 {
		return nil, credentialError(ErrInvalidCredential, "Credential lock timeout must be positive.")
	}
	paths, err := sharedFilePaths(options)
	if err != nil {
		return nil, err
	}
	return &Provider{
		options: options,
		store: &profileStore{
			paths:       paths,
			lockTimeout: options.lockTimeout,
		},
		paths: paths,
	}, nil
}

// Paths returns non-secret storage paths used by the provider.
func (provider *Provider) Paths() FilePaths {
	return provider.paths
}

func invalidCredential(message string) error {
	if message == "" {
		message = "Credential value is invalid."
	}
	return credentialError(ErrInvalidCredential, message)
}

func validateBearerValue(value string) error {
	if value == "" || strings.TrimSpace(value) != value || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return invalidCredential("")
	}
	return nil
}

// ClassifyCredential detects a syntactically valid JWT or opaque API key.
func ClassifyCredential(value string) (Kind, *time.Time, error) {
	if err := validateBearerValue(value); err != nil {
		return "", nil, err
	}
	segments := strings.Split(value, ".")
	if len(segments) != 3 || segments[0] == "" || segments[1] == "" || segments[2] == "" {
		return KindAPIKey, nil, nil
	}
	var header map[string]any
	var payload map[string]any
	headerJSON, headerErr := base64.RawURLEncoding.DecodeString(segments[0])
	payloadJSON, payloadErr := base64.RawURLEncoding.DecodeString(segments[1])
	if headerErr != nil || payloadErr != nil || json.Unmarshal(headerJSON, &header) != nil || json.Unmarshal(payloadJSON, &payload) != nil || header == nil || payload == nil {
		return KindAPIKey, nil, nil
	}
	// No real issuer emits unsigned tokens, and circles-issued JWTs always
	// carry an expiry. Accepting either turned store pollution (an alg:none
	// test fixture without exp) into a credential that never expired.
	algorithm, hasAlgorithm := header["alg"].(string)
	if !hasAlgorithm || strings.EqualFold(algorithm, "none") {
		return "", nil, invalidCredential("JWT is not signed.")
	}
	expiration, exists := payload["exp"]
	if !exists {
		return "", nil, invalidCredential("JWT has no expiration claim.")
	}
	numericExpiration, ok := expiration.(float64)
	if !ok || math.IsNaN(numericExpiration) || math.IsInf(numericExpiration, 0) {
		return "", nil, invalidCredential("JWT expiration claim is invalid.")
	}
	seconds, fractional := math.Modf(numericExpiration)
	expiresAt := time.Unix(int64(seconds), int64(fractional*float64(time.Second)))
	return KindJWT, &expiresAt, nil
}

func resolvedCredential(value string, source Source) (Credential, error) {
	kind, expiresAt, err := ClassifyCredential(value)
	if err != nil {
		return Credential{}, err
	}
	return Credential{Value: value, Kind: kind, ExpiresAt: expiresAt, Source: source}, nil
}

func normalizeExplicitCredential(credential Credential) (Credential, error) {
	kind, parsedExpiration, err := ClassifyCredential(credential.Value)
	if err != nil {
		return Credential{}, err
	}
	if credential.Kind != kind {
		return Credential{}, invalidCredential("Explicit credential kind does not match its value.")
	}
	if credential.ExpiresAt == nil {
		credential.ExpiresAt = parsedExpiration
	}
	credential.Source = Source{Type: SourceExplicit}
	return credential, nil
}

func selectedEnvironmentValue(options providerOptions, canonical, compatibility string) (string, bool) {
	if value, exists := environmentValue(options, canonical); exists {
		return value, true
	}
	return environmentValue(options, compatibility)
}

func requireSelectedValue(value string, selected bool, label string) (string, error) {
	if !selected {
		return "", nil
	}
	if value == "" {
		return "", invalidCredential(label + " is set but empty.")
	}
	return value, nil
}

func validateEndpoint(value, field string) error {
	if value == "" {
		return nil
	}
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "https" && endpoint.Scheme != "http") {
		return invalidCredential("Profile " + field + " is invalid.")
	}
	return nil
}

func validateRawProfile(raw rawProfile) error {
	for key := range raw.config {
		if key != "api_url" && key != "auth_url" && key != "org" {
			return invalidCredential(fmt.Sprintf("Profile '%s' contains an unsupported config field.", raw.name))
		}
	}
	for key := range raw.credentials {
		if key != "access_token" && key != "refresh_token" && key != "api_key" {
			return invalidCredential(fmt.Sprintf("Profile '%s' contains an unsupported credential field.", raw.name))
		}
	}
	if err := validateEndpoint(raw.config["api_url"], "api_url"); err != nil {
		return err
	}
	if err := validateEndpoint(raw.config["auth_url"], "auth_url"); err != nil {
		return err
	}
	if organization := raw.config["org"]; organization != "" && !organizationPattern.MatchString(organization) {
		return invalidCredential(fmt.Sprintf("Profile '%s' org is invalid.", raw.name))
	}
	hasAPIKey := raw.credentials["api_key"] != ""
	hasOAuth := raw.credentials["access_token"] != "" || raw.credentials["refresh_token"] != ""
	if hasAPIKey && hasOAuth {
		return credentialError(ErrAmbiguousCredential, fmt.Sprintf("Profile '%s' contains both OAuth and API-key credentials.", raw.name))
	}
	return nil
}

func isExpired(credential Credential, now time.Time) bool {
	return credential.ExpiresAt != nil && !credential.ExpiresAt.After(now)
}

func refreshFailure(profile, message string) error {
	return credentialError(ErrRefreshFailed, fmt.Sprintf("Profile '%s' %s", profile, message))
}

// SelectedProfileName returns the profile selected by explicit options,
// environment variables, shared current-profile metadata, or legacy default.
func (provider *Provider) SelectedProfileName(ctx context.Context) (string, error) {
	if provider.options.profile != nil {
		if err := validateSelectableProfileName(*provider.options.profile); err != nil {
			return "", err
		}
		return *provider.options.profile, nil
	}
	value, selected := selectedEnvironmentValue(provider.options, "CIRCLES_PROFILE", "CRCL_PROFILE")
	profile, err := requireSelectedValue(value, selected, "Profile environment variable")
	if err != nil {
		return "", err
	}
	if profile != "" {
		if err := validateSelectableProfileName(profile); err != nil {
			return "", err
		}
		return profile, nil
	}
	current, exists, err := provider.store.readCurrentProfile(ctx)
	if err != nil {
		return "", err
	}
	if exists {
		return current, nil
	}
	return "default", nil
}

// CurrentProfile returns the persisted non-secret current-profile selection.
func (provider *Provider) CurrentProfile(ctx context.Context) (string, bool, error) {
	return provider.store.readCurrentProfile(ctx)
}

// SetCurrentProfile makes an existing credential profile the shared default selection.
func (provider *Provider) SetCurrentProfile(ctx context.Context, profile string) error {
	return provider.store.setCurrentProfile(ctx, profile)
}

// Resolve evaluates the shared provider chain.
func (provider *Provider) Resolve(ctx context.Context) (Credential, error) {
	if provider.options.explicitProvider != nil {
		credential, err := provider.options.explicitProvider.Resolve(ctx)
		if err != nil {
			return Credential{}, invalidCredential("Explicit credential provider failed.")
		}
		return normalizeExplicitCredential(credential)
	}
	if provider.options.explicitCredential != nil {
		return resolvedCredential(*provider.options.explicitCredential, Source{Type: SourceExplicit})
	}
	if provider.options.profile != nil {
		if err := validateSelectableProfileName(*provider.options.profile); err != nil {
			return Credential{}, err
		}
		return provider.resolveProfile(ctx, *provider.options.profile)
	}
	value, selected := selectedEnvironmentValue(provider.options, "CIRCLES_AUTH_TOKEN", "CRCL_AUTH_TOKEN")
	environmentCredential, err := requireSelectedValue(value, selected, "Credential environment variable")
	if err != nil {
		return Credential{}, err
	}
	if environmentCredential != "" {
		return resolvedCredential(environmentCredential, Source{Type: SourceEnvironment})
	}
	profile, err := provider.SelectedProfileName(ctx)
	if err != nil {
		return Credential{}, err
	}
	return provider.resolveProfile(ctx, profile)
}

// GetProfile returns only a selected profile's non-secret settings.
func (provider *Provider) GetProfile(ctx context.Context) (*StoredProfile, error) {
	profile, err := provider.SelectedProfileName(ctx)
	if err != nil {
		return nil, err
	}
	return provider.store.readProfile(ctx, profile)
}

// Refresh forces OAuth refresh for the selected profile.
func (provider *Provider) Refresh(ctx context.Context) (Credential, error) {
	if provider.options.explicitCredential != nil || provider.options.explicitProvider != nil {
		return Credential{}, credentialError(ErrRefreshFailed, "An explicit credential cannot be refreshed by the shared profile provider.")
	}
	if provider.options.profile == nil {
		if _, selected := selectedEnvironmentValue(provider.options, "CIRCLES_AUTH_TOKEN", "CRCL_AUTH_TOKEN"); selected {
			return Credential{}, credentialError(ErrRefreshFailed, "An environment credential cannot be refreshed by the shared profile provider.")
		}
	}
	profile, err := provider.SelectedProfileName(ctx)
	if err != nil {
		return Credential{}, err
	}
	raw, err := provider.store.readRawProfile(ctx, profile)
	if err != nil {
		return Credential{}, err
	}
	if err := validateRawProfile(raw); err != nil {
		return Credential{}, err
	}
	return provider.refreshProfile(ctx, profile, raw.credentials["refresh_token"])
}

// UpdateProfile atomically replaces each changed profile file.
func (provider *Provider) UpdateProfile(ctx context.Context, update ProfileUpdate) error {
	if update.Config != nil {
		if err := validateEndpoint(update.Config.APIURL, "api_url"); err != nil {
			return err
		}
		if err := validateEndpoint(update.Config.AuthURL, "auth_url"); err != nil {
			return err
		}
		if update.Config.Org != "" && !organizationPattern.MatchString(update.Config.Org) {
			return invalidCredential("Profile org is invalid.")
		}
	}
	if update.Credentials != nil {
		hasAPIKey := update.Credentials.APIKey != ""
		hasOAuth := update.Credentials.AccessToken != "" || update.Credentials.RefreshToken != ""
		if hasAPIKey && hasOAuth {
			return credentialError(ErrAmbiguousCredential, "Profile update contains both OAuth and API-key credentials.")
		}
		if !hasAPIKey && update.Credentials.AccessToken == "" {
			return invalidCredential("Profile update has no credential.")
		}
		if hasAPIKey {
			kind, _, err := ClassifyCredential(update.Credentials.APIKey)
			if err != nil || kind != KindAPIKey {
				return invalidCredential("A profile api_key must be opaque.")
			}
		} else {
			kind, _, err := ClassifyCredential(update.Credentials.AccessToken)
			if err != nil || kind != KindJWT {
				return invalidCredential("A profile access_token must be a JWT.")
			}
			if update.Credentials.RefreshToken != "" {
				if err := validateBearerValue(update.Credentials.RefreshToken); err != nil {
					return err
				}
			}
		}
	}
	profile, err := provider.SelectedProfileName(ctx)
	if err != nil {
		return err
	}
	return provider.store.updateProfile(ctx, profile, update)
}

// DeleteProfile removes the selected canonical profile while retaining migration history.
func (provider *Provider) DeleteProfile(ctx context.Context) error {
	profile, err := provider.SelectedProfileName(ctx)
	if err != nil {
		return err
	}
	return provider.store.deleteProfile(ctx, profile)
}

// ClearProfiles removes all canonical profiles while retaining legacy rollback files.
func (provider *Provider) ClearProfiles(ctx context.Context) error {
	return provider.store.clearProfiles(ctx)
}

func (provider *Provider) resolveProfile(ctx context.Context, profile string) (Credential, error) {
	raw, err := provider.store.readRawProfile(ctx, profile)
	if err != nil {
		return Credential{}, err
	}
	if err := validateRawProfile(raw); err != nil {
		return Credential{}, err
	}
	source := Source{Type: SourceProfile, Profile: profile}
	if !raw.exists || len(raw.credentials) == 0 {
		return Credential{}, credentialError(
			ErrCredentialNotFound,
			fmt.Sprintf("No credential was found for profile '%s'. Set CIRCLES_AUTH_TOKEN or run 'crcl login --profile %s'.", profile, profile),
		)
	}
	if apiKey := raw.credentials["api_key"]; apiKey != "" {
		credential, err := resolvedCredential(apiKey, source)
		if err != nil {
			return Credential{}, err
		}
		if credential.Kind != KindAPIKey {
			return Credential{}, invalidCredential(fmt.Sprintf("Profile '%s' api_key must be opaque.", profile))
		}
		return credential, nil
	}
	if accessToken := raw.credentials["access_token"]; accessToken != "" {
		// An invalid stored access token (unsigned, malformed, no expiry) is
		// treated like an expired one: fall through to the refresh path so a
		// polluted store heals itself instead of wedging every caller.
		credential, err := resolvedCredential(accessToken, source)
		if err != nil && !IsError(err, ErrInvalidCredential) {
			return Credential{}, err
		}
		if err == nil {
			if credential.Kind != KindJWT {
				return Credential{}, invalidCredential(fmt.Sprintf("Profile '%s' access_token must be a JWT.", profile))
			}
			if !isExpired(credential, provider.options.now()) {
				return credential, nil
			}
		}
	}
	refreshToken := raw.credentials["refresh_token"]
	if refreshToken == "" {
		return Credential{}, refreshFailure(profile, "has no usable access token or refresh token.")
	}
	return provider.refreshProfile(ctx, profile, refreshToken)
}

func (provider *Provider) refreshProfile(ctx context.Context, profile, observedRefreshToken string) (Credential, error) {
	if err := provider.store.migrateLegacyProfiles(ctx); err != nil {
		return Credential{}, err
	}
	release, err := provider.store.acquireLock(ctx)
	if err != nil {
		return Credential{}, err
	}
	defer release()
	current, err := provider.store.readRawProfileWithoutMigration(profile)
	if err != nil {
		return Credential{}, err
	}
	if err := validateRawProfile(current); err != nil {
		return Credential{}, err
	}
	source := Source{Type: SourceProfile, Profile: profile}
	refreshToken := current.credentials["refresh_token"]
	if observedRefreshToken != "" && refreshToken != "" && observedRefreshToken != refreshToken && current.credentials["access_token"] != "" {
		rotated, resolveErr := resolvedCredential(current.credentials["access_token"], source)
		if resolveErr == nil && rotated.Kind == KindJWT && !isExpired(rotated, provider.options.now()) {
			return rotated, nil
		}
	}
	if refreshToken == "" {
		return Credential{}, refreshFailure(profile, "cannot be refreshed because its refresh token is missing.")
	}
	if err := validateBearerValue(refreshToken); err != nil {
		return Credential{}, refreshFailure(profile, "contains an invalid refresh token.")
	}
	authURL := strings.TrimSuffix(current.config["auth_url"], "/")
	if authURL == "" {
		authURL = "https://auth.circles.ac"
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {provider.options.clientID},
		"refresh_token": {refreshToken},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return Credential{}, refreshFailure(profile, "could not create the OAuth request.")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := provider.options.httpClient.Do(request)
	if err != nil {
		return Credential{}, refreshFailure(profile, "could not reach the OAuth issuer.")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return Credential{}, refreshFailure(profile, fmt.Sprintf("refresh was rejected with HTTP %d.", response.StatusCode))
	}
	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(&payload); err != nil {
		return Credential{}, refreshFailure(profile, "received an invalid refresh response.")
	}
	if payload.RefreshToken == "" {
		payload.RefreshToken = refreshToken
	}
	if err := validateBearerValue(payload.AccessToken); err != nil {
		return Credential{}, refreshFailure(profile, "received invalid rotated credentials.")
	}
	if err := validateBearerValue(payload.RefreshToken); err != nil {
		return Credential{}, refreshFailure(profile, "received invalid rotated credentials.")
	}
	kind, _, err := ClassifyCredential(payload.AccessToken)
	if err != nil || kind != KindJWT {
		return Credential{}, refreshFailure(profile, "received invalid rotated credentials.")
	}
	if err := provider.store.replaceOAuthCredentials(profile, payload.AccessToken, payload.RefreshToken); err != nil {
		return Credential{}, err
	}
	return resolvedCredential(payload.AccessToken, source)
}
