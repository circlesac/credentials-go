package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	validJWT   = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ2YWxpZCIsImV4cCI6NDEwMjQ0NDgwMH0.signature"
	expiredJWT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJleHBpcmVkIiwiZXhwIjoxfQ.signature"
)

type expectedSource struct {
	Type    string `json:"type"`
	Profile string `json:"profile"`
}

type expectedCredential struct {
	Value  string         `json:"value"`
	Kind   string         `json:"kind"`
	Source expectedSource `json:"source"`
}

type resolutionCase struct {
	Name               string                       `json:"name"`
	ExplicitCredential *string                      `json:"explicit_credential"`
	ExplicitProfile    *string                      `json:"explicit_profile"`
	Profile            string                       `json:"profile"`
	Env                map[string]string            `json:"env"`
	Profiles           map[string]map[string]string `json:"profiles"`
	Config             string                       `json:"config"`
	Credentials        string                       `json:"credentials"`
	Expected           *expectedCredential          `json:"expected"`
	Error              ErrorCode                    `json:"error"`
	ExpectNoDiskWrite  bool                         `json:"expect_no_disk_write"`
	SecretSafe         []string                     `json:"secret_safe"`
	MessageContains    []string                     `json:"message_contains"`
}

func readContract(t *testing.T, name string, target any) {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("schemas", name))
	if err != nil {
		t.Fatalf("shared contract %s was not found: %v", name, err)
	}
	if err := json.Unmarshal(contents, target); err != nil {
		t.Fatal(err)
	}
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func serializeProfiles(profiles map[string]map[string]string) string {
	var builder strings.Builder
	first := true
	for profile, values := range profiles {
		if !first {
			builder.WriteString("\n")
		}
		first = false
		fmt.Fprintf(&builder, "[%s]\n", profile)
		for key, value := range values {
			fmt.Fprintf(&builder, "%s = %s\n", key, value)
		}
	}
	return builder.String()
}

func errorCode(t *testing.T, err error) ErrorCode {
	t.Helper()
	if err == nil {
		t.Fatal("expected credential error")
	}
	var credentialFailure *Error
	if !errors.As(err, &credentialFailure) {
		t.Fatalf("expected *credentials.Error, got %T: %v", err, err)
	}
	return credentialFailure.Code
}

func executeResolutionCase(t *testing.T, testCase resolutionCase) {
	t.Helper()
	home := t.TempDir()
	if testCase.Config != "" {
		writeTestFile(t, filepath.Join(home, ".crcl", "config"), testCase.Config)
	}
	credentials := testCase.Credentials
	if credentials == "" {
		credentials = serializeProfiles(testCase.Profiles)
	}
	if credentials != "" {
		writeTestFile(t, filepath.Join(home, ".crcl", "credentials"), credentials)
	}
	options := []Option{WithHomeDir(home), WithEnvironment(testCase.Env)}
	if testCase.ExplicitCredential != nil {
		options = append(options, WithCredential(*testCase.ExplicitCredential))
	}
	if testCase.ExplicitProfile != nil {
		options = append(options, WithProfile(*testCase.ExplicitProfile))
	}
	provider, err := New(options...)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := provider.Resolve(context.Background())
	if testCase.Error != "" {
		if code := errorCode(t, err); code != testCase.Error {
			t.Fatalf("got error code %s, want %s", code, testCase.Error)
		}
		for _, secret := range testCase.SecretSafe {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error contains secret %q", secret)
			}
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}
		if credential.Value != testCase.Expected.Value ||
			string(credential.Kind) != testCase.Expected.Kind ||
			string(credential.Source.Type) != testCase.Expected.Source.Type ||
			credential.Source.Profile != testCase.Expected.Source.Profile {
			t.Fatalf("resolved %#v, want %#v", credential, *testCase.Expected)
		}
	}
	if testCase.ExpectNoDiskWrite {
		if _, err := os.Stat(filepath.Join(home, ".crcl")); !os.IsNotExist(err) {
			t.Fatalf("environment resolution wrote canonical directory: %v", err)
		}
	}
}

func TestSharedManifest(t *testing.T) {
	var manifest struct {
		Version int      `json:"version"`
		Files   []string `json:"files"`
	}
	readContract(t, "manifest.json", &manifest)
	expected := []string{
		"precedence.json",
		"profiles.json",
		"classification.json",
		"refresh.json",
		"migration.json",
		"errors.json",
		"selection.json",
	}
	if manifest.Version != 1 || !reflect.DeepEqual(manifest.Files, expected) {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	for _, file := range manifest.Files {
		var versioned struct {
			Version int `json:"version"`
		}
		readContract(t, file, &versioned)
		if versioned.Version != 1 {
			t.Fatalf("%s has version %d", file, versioned.Version)
		}
	}
}

func TestSharedSelectionCases(t *testing.T) {
	var data struct {
		Cases []resolutionCase `json:"cases"`
	}
	readContract(t, "selection.json", &data)
	for _, testCase := range data.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			executeResolutionCase(t, testCase)
		})
	}
}

func TestCurrentProfileManagement(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	writeTestFile(t, filepath.Join(home, ".crcl", "config"), "[prod:alice@example.com]\norg = example\n")
	writeTestFile(t, filepath.Join(home, ".crcl", "credentials"), "[prod:alice@example.com]\napi_key = example-key\n\n[default]\napi_key = default-key\n")
	provider, err := New(WithHomeDir(home), WithEnvironment(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.SetCurrentProfile(ctx, "missing@example.com"); !IsError(err, ErrCredentialNotFound) {
		t.Fatalf("missing profile selection returned %v", err)
	}
	if err := provider.SetCurrentProfile(ctx, "prod:alice@example.com"); err != nil {
		t.Fatal(err)
	}
	current, exists, err := provider.CurrentProfile(ctx)
	if err != nil || !exists || current != "prod:alice@example.com" {
		t.Fatalf("current profile = %q, %v, %v", current, exists, err)
	}
	selected, err := provider.SelectedProfileName(ctx)
	if err != nil || selected != "prod:alice@example.com" {
		t.Fatalf("selected profile = %q, %v", selected, err)
	}
	credential, err := provider.Resolve(ctx)
	if err != nil || credential.Value != "example-key" {
		t.Fatalf("resolved credential = %#v, %v", credential, err)
	}
	stored, err := os.ReadFile(filepath.Join(home, ".crcl", "credentials"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(stored), "example-key") != 1 {
		t.Fatalf("current profile selection duplicated credentials:\n%s", stored)
	}
	if err := provider.DeleteProfile(ctx); err != nil {
		t.Fatal(err)
	}
	current, exists, err = provider.CurrentProfile(ctx)
	if err != nil || exists || current != "" {
		t.Fatalf("deleted current profile left pointer = %q, %v, %v", current, exists, err)
	}
	credential, err = provider.Resolve(ctx)
	if err != nil || credential.Value != "default-key" {
		t.Fatalf("legacy default fallback = %#v, %v", credential, err)
	}
}

func TestSharedPrecedenceCases(t *testing.T) {
	var data struct {
		Cases []resolutionCase `json:"cases"`
	}
	readContract(t, "precedence.json", &data)
	for _, testCase := range data.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			executeResolutionCase(t, testCase)
		})
	}
}

func TestSharedClassificationCases(t *testing.T) {
	var data struct {
		Cases []struct {
			Name     string `json:"name"`
			Value    string `json:"value"`
			Expected *struct {
				Kind          string `json:"kind"`
				ExpiresAtUnix *int64 `json:"expires_at_unix"`
			} `json:"expected"`
			Error      ErrorCode `json:"error"`
			SecretSafe bool      `json:"secret_safe"`
		} `json:"cases"`
	}
	readContract(t, "classification.json", &data)
	for _, testCase := range data.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			kind, expiresAt, err := ClassifyCredential(testCase.Value)
			if testCase.Error != "" {
				if code := errorCode(t, err); code != testCase.Error {
					t.Fatalf("got error code %s, want %s", code, testCase.Error)
				}
				if testCase.SecretSafe && strings.Contains(err.Error(), testCase.Value) {
					t.Fatal("classification error contains secret")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(kind) != testCase.Expected.Kind {
				t.Fatalf("got kind %s, want %s", kind, testCase.Expected.Kind)
			}
			if testCase.Expected.ExpiresAtUnix == nil {
				if expiresAt != nil {
					t.Fatalf("unexpected expiration %s", expiresAt)
				}
			} else if expiresAt == nil || expiresAt.Unix() != *testCase.Expected.ExpiresAtUnix {
				t.Fatalf("got expiration %v, want %d", expiresAt, *testCase.Expected.ExpiresAtUnix)
			}
		})
	}
}

func TestSharedProfileCases(t *testing.T) {
	var data struct {
		Cases []resolutionCase `json:"cases"`
	}
	readContract(t, "profiles.json", &data)
	for _, testCase := range data.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			testCase.ExplicitProfile = &testCase.Profile
			executeResolutionCase(t, testCase)
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type staticCredentialProvider struct {
	credential Credential
}

func (provider staticCredentialProvider) Resolve(context.Context) (Credential, error) {
	return provider.credential, nil
}

func TestExplicitProviderIsNormalizedAndWins(t *testing.T) {
	provider, err := New(
		WithCredentialProvider(staticCredentialProvider{credential: Credential{
			Value:  "provider-key",
			Kind:   KindAPIKey,
			Source: Source{Type: SourceEnvironment},
		}}),
		WithProfile("missing"),
		WithEnvironment(map[string]string{"CIRCLES_AUTH_TOKEN": "environment-key"}),
		WithHomeDir(t.TempDir()),
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := provider.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if credential.Value != "provider-key" || credential.Source != (Source{Type: SourceExplicit}) {
		t.Fatalf("explicit provider was not normalized: %#v", credential)
	}
}

func TestSharedRefreshCases(t *testing.T) {
	var data struct {
		Cases []struct {
			Name                       string         `json:"name"`
			Profile                    string         `json:"profile"`
			NowUnix                    int64          `json:"now_unix"`
			AuthURL                    string         `json:"auth_url"`
			AccessToken                string         `json:"access_token"`
			RefreshToken               string         `json:"refresh_token"`
			ResponseStatus             int            `json:"response_status"`
			Response                   map[string]any `json:"response"`
			ExpectedRequestURL         string         `json:"expected_request_url"`
			ExpectedClientID           string         `json:"expected_client_id"`
			ExpectedValue              string         `json:"expected_value"`
			ExpectedStoredRefreshToken string         `json:"expected_stored_refresh_token"`
			Error                      ErrorCode      `json:"error"`
			SecretSafe                 []string       `json:"secret_safe"`
		} `json:"cases"`
	}
	readContract(t, "refresh.json", &data)
	for _, testCase := range data.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			home := t.TempDir()
			if testCase.AuthURL != "" {
				writeTestFile(t, filepath.Join(home, ".crcl", "config"), fmt.Sprintf("[%s]\nauth_url = %s\n", testCase.Profile, testCase.AuthURL))
			}
			writeTestFile(
				t,
				filepath.Join(home, ".crcl", "credentials"),
				fmt.Sprintf("[%s]\naccess_token = %s\nrefresh_token = %s\n", testCase.Profile, testCase.AccessToken, testCase.RefreshToken),
			)
			responseBody, err := json.Marshal(testCase.Response)
			if err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				expectedURL := testCase.ExpectedRequestURL
				if expectedURL == "" {
					expectedURL = "https://auth.circles.ac/token"
				}
				if request.URL.String() != expectedURL {
					t.Errorf("request URL %s, want %s", request.URL, expectedURL)
				}
				if err := request.ParseForm(); err != nil {
					t.Error(err)
				}
				expectedClientID := testCase.ExpectedClientID
				if expectedClientID == "" {
					expectedClientID = "circles-api"
				}
				if request.Form.Get("grant_type") != "refresh_token" ||
					request.Form.Get("client_id") != expectedClientID ||
					request.Form.Get("refresh_token") != testCase.RefreshToken {
					t.Errorf("unexpected refresh request: %v", request.Form)
				}
				return &http.Response{
					StatusCode: testCase.ResponseStatus,
					Body:       io.NopCloser(bytes.NewReader(responseBody)),
					Header:     make(http.Header),
					Request:    request,
				}, nil
			})}
			provider, err := New(
				WithProfile(testCase.Profile),
				WithHomeDir(home),
				WithEnvironment(map[string]string{}),
				WithHTTPClient(client),
				WithNow(func() time.Time { return time.Unix(testCase.NowUnix, 0) }),
			)
			if err != nil {
				t.Fatal(err)
			}
			credential, err := provider.Resolve(context.Background())
			if testCase.Error != "" {
				if code := errorCode(t, err); code != testCase.Error {
					t.Fatalf("got error code %s, want %s", code, testCase.Error)
				}
				for _, secret := range testCase.SecretSafe {
					if strings.Contains(err.Error(), secret) {
						t.Fatalf("error contains secret %q", secret)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if credential.Value != testCase.ExpectedValue ||
				credential.Source != (Source{Type: SourceProfile, Profile: testCase.Profile}) {
				t.Fatalf("unexpected credential: %#v", credential)
			}
			stored, err := os.ReadFile(filepath.Join(home, ".crcl", "credentials"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(stored), "access_token = "+testCase.ExpectedValue) ||
				!strings.Contains(string(stored), "refresh_token = "+testCase.ExpectedStoredRefreshToken) {
				t.Fatalf("unexpected stored credentials:\n%s", stored)
			}
		})
	}
}

func TestSharedMigrationCases(t *testing.T) {
	var data struct {
		Cases []struct {
			Name                     string          `json:"name"`
			CanonicalCredentials     string          `json:"canonical_credentials"`
			LegacyConfig             string          `json:"legacy_config"`
			LegacyCredentials        string          `json:"legacy_credentials"`
			LegacyJSON               json.RawMessage `json:"legacy_json"`
			Profile                  string          `json:"profile"`
			ExpectedValue            string          `json:"expected_value"`
			ExpectedProfiles         []string        `json:"expected_profiles"`
			ForbiddenCanonicalValues []string        `json:"forbidden_canonical_values"`
			Repeat                   bool            `json:"repeat"`
			PreserveLegacy           bool            `json:"preserve_legacy"`
		} `json:"cases"`
	}
	readContract(t, "migration.json", &data)
	for _, testCase := range data.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			home := t.TempDir()
			legacyDirectory := filepath.Join(home, ".config", "crcl")
			if testCase.CanonicalCredentials != "" {
				writeTestFile(t, filepath.Join(home, ".crcl", "credentials"), testCase.CanonicalCredentials)
			}
			if testCase.LegacyConfig != "" {
				writeTestFile(t, filepath.Join(legacyDirectory, "config"), testCase.LegacyConfig)
			}
			if testCase.LegacyCredentials != "" {
				writeTestFile(t, filepath.Join(legacyDirectory, "credentials"), testCase.LegacyCredentials)
			}
			if len(testCase.LegacyJSON) > 0 {
				writeTestFile(t, filepath.Join(legacyDirectory, "config.json"), string(testCase.LegacyJSON))
			}
			legacyBefore := map[string][]byte{}
			for _, name := range []string{"config", "credentials", "config.json"} {
				path := filepath.Join(legacyDirectory, name)
				if contents, err := os.ReadFile(path); err == nil {
					legacyBefore[path] = contents
				}
			}
			resolve := func() Credential {
				provider, err := New(
					WithProfile(testCase.Profile),
					WithHomeDir(home),
					WithEnvironment(map[string]string{}),
				)
				if err != nil {
					t.Fatal(err)
				}
				credential, err := provider.Resolve(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				return credential
			}
			if credential := resolve(); credential.Value != testCase.ExpectedValue {
				t.Fatalf("resolved %q, want %q", credential.Value, testCase.ExpectedValue)
			}
			canonicalPath := filepath.Join(home, ".crcl", "credentials")
			canonicalBefore, err := os.ReadFile(canonicalPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, profile := range testCase.ExpectedProfiles {
				if !strings.Contains(string(canonicalBefore), "["+profile+"]") {
					t.Fatalf("canonical credentials missing profile %q:\n%s", profile, canonicalBefore)
				}
			}
			for _, value := range testCase.ForbiddenCanonicalValues {
				if strings.Contains(string(canonicalBefore), value) {
					t.Fatalf("canonical credentials contain forbidden legacy value %q", value)
				}
			}
			if testCase.Repeat {
				if credential := resolve(); credential.Value != testCase.ExpectedValue {
					t.Fatalf("repeat resolved %q, want %q", credential.Value, testCase.ExpectedValue)
				}
				canonicalAfter, err := os.ReadFile(canonicalPath)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(canonicalBefore, canonicalAfter) {
					t.Fatalf("repeat migration changed canonical file:\n%s\n%s", canonicalBefore, canonicalAfter)
				}
			}
			if testCase.PreserveLegacy {
				for path, contents := range legacyBefore {
					after, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(contents, after) {
						t.Fatalf("legacy file %s changed or disappeared", path)
					}
				}
			}
		})
	}
}

func TestSharedErrorCases(t *testing.T) {
	var data struct {
		StableCodes []ErrorCode      `json:"stable_codes"`
		Cases       []resolutionCase `json:"cases"`
	}
	readContract(t, "errors.json", &data)
	expectedCodes := []ErrorCode{
		ErrCredentialNotFound,
		ErrInvalidCredential,
		ErrAmbiguousCredential,
		ErrRefreshFailed,
		ErrProfileConflict,
		ErrCredentialStorage,
	}
	if !reflect.DeepEqual(data.StableCodes, expectedCodes) {
		t.Fatalf("stable codes %#v, want %#v", data.StableCodes, expectedCodes)
	}
	for _, testCase := range data.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			home := t.TempDir()
			options := []Option{WithHomeDir(home), WithEnvironment(map[string]string{})}
			if testCase.ExplicitCredential != nil {
				options = append(options, WithCredential(*testCase.ExplicitCredential))
			}
			provider, err := New(options...)
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider.Resolve(context.Background())
			if code := errorCode(t, err); code != testCase.Error {
				t.Fatalf("got error code %s, want %s", code, testCase.Error)
			}
			for _, secret := range testCase.SecretSafe {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error contains secret %q", secret)
				}
			}
			for _, text := range testCase.MessageContains {
				if !strings.Contains(err.Error(), text) {
					t.Fatalf("error %q does not contain %q", err, text)
				}
			}
		})
	}
}

func TestConcurrentRefreshUsesOneRotatedTokenPair(t *testing.T) {
	home := t.TempDir()
	writeTestFile(t, filepath.Join(home, ".crcl", "credentials"), "[default]\naccess_token = "+expiredJWT+"\nrefresh_token = old-refresh\n")
	var calls int32
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(60 * time.Millisecond)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"` + validJWT + `","refresh_token":"new-refresh"}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}
	first, err := New(WithHomeDir(home), WithEnvironment(map[string]string{}), WithHTTPClient(client))
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(WithHomeDir(home), WithEnvironment(map[string]string{}), WithHTTPClient(client))
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan Credential, 2)
	failures := make(chan error, 2)
	for _, provider := range []*Provider{first, second} {
		go func(provider *Provider) {
			credential, resolveErr := provider.Resolve(context.Background())
			if resolveErr != nil {
				failures <- resolveErr
				return
			}
			results <- credential
		}(provider)
	}
	for received := 0; received < 2; received++ {
		select {
		case failure := <-failures:
			t.Fatal(failure)
		case credential := <-results:
			if credential.Value != validJWT {
				t.Fatalf("resolved %q, want rotated JWT", credential.Value)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent refresh")
		}
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("OAuth issuer called %d times, want once", atomic.LoadInt32(&calls))
	}
	stored, err := os.ReadFile(filepath.Join(home, ".crcl", "credentials"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stored), "new-refresh") || strings.Contains(string(stored), "old-refresh") {
		t.Fatalf("stale refresh token persisted:\n%s", stored)
	}
}

func TestMigrationPermissionsAndDeletionMarker(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("POSIX permission assertion")
	}
	home := t.TempDir()
	legacyPath := filepath.Join(home, ".config", "crcl", "credentials")
	legacyContents := "[default]\napi_key = legacy-key\n"
	writeTestFile(t, legacyPath, legacyContents)
	provider, err := New(WithHomeDir(home), WithEnvironment(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := provider.DeleteProfile(context.Background()); err != nil {
		t.Fatal(err)
	}
	next, err := New(WithHomeDir(home), WithEnvironment(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := next.Resolve(context.Background()); !IsError(err, ErrCredentialNotFound) {
		t.Fatalf("deleted legacy profile reappeared: %v", err)
	}
	if contents, err := os.ReadFile(legacyPath); err != nil || string(contents) != legacyContents {
		t.Fatal("legacy rollback file changed")
	}
	for _, check := range []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Join(home, ".crcl"), 0o700},
		{filepath.Join(home, ".crcl", "credentials"), 0o600},
		{filepath.Join(home, ".crcl", "credentials.migrated"), 0o600},
	} {
		info, err := os.Stat(check.path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != check.mode {
			t.Fatalf("%s mode %o, want %o", check.path, info.Mode().Perm(), check.mode)
		}
	}
}

func TestEnvironmentPathOverrides(t *testing.T) {
	home := t.TempDir()
	configFile := filepath.Join(home, "custom", "config.ini")
	credentialsFile := filepath.Join(home, "secrets", "credentials.ini")
	writeTestFile(t, configFile, "[default]\norg = custom\n")
	writeTestFile(t, credentialsFile, "[default]\napi_key = custom-key\n")
	provider, err := New(
		WithHomeDir(home),
		WithEnvironment(map[string]string{
			"CIRCLES_CONFIG_FILE":             configFile,
			"CIRCLES_SHARED_CREDENTIALS_FILE": credentialsFile,
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := provider.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	profile, err := provider.GetProfile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if credential.Value != "custom-key" || profile == nil || profile.Config.Org != "custom" {
		t.Fatalf("path override resolved unexpected values: %#v %#v", credential, profile)
	}
	if provider.Paths().ConfigFile != configFile || provider.Paths().CredentialsFile != credentialsFile {
		t.Fatalf("path overrides not exposed: %#v", provider.Paths())
	}
}
