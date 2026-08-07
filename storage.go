package credentials

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type rawProfile struct {
	name        string
	config      map[string]string
	credentials map[string]string
	exists      bool
}

type legacyProfile struct {
	config      map[string]string
	credentials map[string]string
}

type profileStore struct {
	paths       FilePaths
	lockTimeout time.Duration
	migrationMu sync.Mutex
	migrated    bool
}

const (
	metadataSection   = "__circles__"
	currentProfileKey = "current_profile"
)

func environmentValue(options providerOptions, name string) (string, bool) {
	if options.env != nil {
		value, exists := options.env[name]
		return value, exists
	}
	return os.LookupEnv(name)
}

func sharedFilePaths(options providerOptions) (FilePaths, error) {
	home := options.homeDir
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return FilePaths{}, storageError("Credential storage failed while finding the home directory.", err)
		}
	}
	xdg, exists := environmentValue(options, "XDG_CONFIG_HOME")
	if !exists || xdg == "" {
		xdg = filepath.Join(home, ".config")
	}
	legacyRoot := filepath.Join(xdg, "crcl")

	configOverride := options.configFile
	if configOverride == nil {
		if value, selected := environmentValue(options, "CIRCLES_CONFIG_FILE"); selected {
			configOverride = &value
		}
	}
	credentialsOverride := options.credentialsFile
	if credentialsOverride == nil {
		if value, selected := environmentValue(options, "CIRCLES_SHARED_CREDENTIALS_FILE"); selected {
			credentialsOverride = &value
		}
	}
	if (configOverride != nil && *configOverride == "") || (credentialsOverride != nil && *credentialsOverride == "") {
		return FilePaths{}, credentialError(ErrInvalidCredential, "Shared credential file path overrides must not be empty.")
	}
	configFile := filepath.Join(home, ".crcl", "config")
	if configOverride != nil {
		configFile = *configOverride
	}
	credentialsFile := filepath.Join(home, ".crcl", "credentials")
	if credentialsOverride != nil {
		credentialsFile = *credentialsOverride
	}
	var err error
	if configFile, err = filepath.Abs(configFile); err != nil {
		return FilePaths{}, storageError("Credential storage failed while resolving the config path.", err)
	}
	if credentialsFile, err = filepath.Abs(credentialsFile); err != nil {
		return FilePaths{}, storageError("Credential storage failed while resolving the credentials path.", err)
	}
	if configFile == credentialsFile {
		return FilePaths{}, credentialError(ErrProfileConflict, "The shared config and credentials files must use different paths.")
	}
	legacyConfig, _ := filepath.Abs(filepath.Join(legacyRoot, "config"))
	legacyCredentials, _ := filepath.Abs(filepath.Join(legacyRoot, "credentials"))
	legacyJSON, _ := filepath.Abs(filepath.Join(legacyRoot, "config.json"))
	return FilePaths{
		ConfigFile:            configFile,
		CredentialsFile:       credentialsFile,
		LegacyConfigFile:      legacyConfig,
		LegacyCredentialsFile: legacyCredentials,
		LegacyJSONFile:        legacyJSON,
	}, nil
}

func ensureDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

func readINIFile(path string) (iniData, error) {
	contents, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return iniData{}, nil
	}
	if err != nil {
		return nil, err
	}
	return parseINI(string(contents))
}

func atomicWrite(path string, contents string) error {
	directory := filepath.Dir(path)
	if err := ensureDirectory(directory); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.WriteString(contents); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	if directoryHandle, err := os.Open(directory); err == nil {
		_ = directoryHandle.Sync()
		_ = directoryHandle.Close()
	}
	return nil
}

func atomicWriteINI(path string, data iniData) error {
	contents, err := serializeINI(data)
	if err != nil {
		return err
	}
	return atomicWrite(path, contents)
}

func randomOwner() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%s", os.Getpid(), hex.EncodeToString(value)), nil
}

func (store *profileStore) acquireLock(ctx context.Context) (func(), error) {
	lockPath := store.paths.CredentialsFile + ".lock"
	if err := ensureDirectory(filepath.Dir(lockPath)); err != nil {
		return nil, storageError("Credential storage failed while locking the credentials file.", err)
	}
	owner, err := randomOwner()
	if err != nil {
		return nil, storageError("Credential storage failed while locking the credentials file.", err)
	}
	started := time.Now()
	staleAfter := 120 * time.Second
	if store.lockTimeout*6 > staleAfter {
		staleAfter = store.lockTimeout * 6
	}
	for {
		err = os.Mkdir(lockPath, 0o700)
		if err == nil {
			if err = os.WriteFile(filepath.Join(lockPath, "owner"), []byte(owner), 0o600); err != nil {
				_ = os.RemoveAll(lockPath)
				return nil, storageError("Credential storage failed while locking the credentials file.", err)
			}
			break
		}
		if !os.IsExist(err) {
			return nil, storageError("Credential storage failed while locking the credentials file.", err)
		}
		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > staleAfter {
			_ = os.RemoveAll(lockPath)
			continue
		}
		if time.Since(started) >= store.lockTimeout {
			return nil, credentialError(ErrCredentialStorage, "Timed out waiting for the shared credentials lock.")
		}
		select {
		case <-ctx.Done():
			return nil, credentialError(ErrCredentialStorage, "Canceled while waiting for the shared credentials lock.")
		case <-time.After(20 * time.Millisecond):
		}
	}
	return func() {
		current, readErr := os.ReadFile(filepath.Join(lockPath, "owner"))
		if readErr == nil && string(current) == owner {
			_ = os.RemoveAll(lockPath)
		}
	}, nil
}

func readMigrationMarker(path string) (map[string]bool, error) {
	contents, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	profiles := map[string]bool{}
	for _, profile := range strings.Fields(string(contents)) {
		if err := validateSelectableProfileName(profile); err != nil {
			return nil, err
		}
		profiles[profile] = true
	}
	return profiles, nil
}

func writeMigrationMarker(path string, profiles map[string]bool) error {
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return atomicWrite(path, strings.Join(names, "\n")+"\n")
}

var legacyProfileSuffix = regexp.MustCompile(`\[([^\]]+)\]$`)

func legacyProfileName(key string) (string, error) {
	match := legacyProfileSuffix.FindStringSubmatch(key)
	profile := "default"
	if len(match) == 2 {
		profile = match[1]
	}
	if err := validateSelectableProfileName(profile); err != nil {
		return "", err
	}
	return profile, nil
}

func stringField(entry map[string]any, name string) string {
	value, _ := entry[name].(string)
	return value
}

func legacyEntry(entry map[string]any) legacyProfile {
	config := map[string]string{}
	credentials := map[string]string{}
	if value := stringField(entry, "api_url"); value != "" {
		config["api_url"] = value
	}
	if value := stringField(entry, "auth_url"); value != "" {
		config["auth_url"] = value
	}
	if organizations, ok := entry["orgs"].(map[string]any); ok {
		for _, value := range organizations {
			organization, ok := value.(map[string]any)
			if !ok || organization["default"] != true {
				continue
			}
			if slug, ok := organization["slug"].(string); ok && slug != "" {
				config["org"] = slug
			}
			break
		}
	}
	if value := stringField(entry, "access_token"); value != "" {
		credentials["access_token"] = value
	}
	if value := stringField(entry, "refresh_token"); value != "" {
		credentials["refresh_token"] = value
	}
	if value := stringField(entry, "api_key"); value != "" {
		credentials["api_key"] = value
	}
	return legacyProfile{config: config, credentials: credentials}
}

func readLegacyJSON(path string) (map[string]legacyProfile, error) {
	contents, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]legacyProfile{}, nil
	}
	if err != nil {
		return nil, err
	}
	var parsed map[string]any
	if err := json.Unmarshal(contents, &parsed); err != nil {
		return nil, err
	}
	result := map[string]legacyProfile{}
	if accounts, ok := parsed["accounts"].(map[string]any); ok {
		for key, value := range accounts {
			entry, ok := value.(map[string]any)
			if !ok {
				continue
			}
			profile, err := legacyProfileName(key)
			if err != nil {
				return nil, err
			}
			if _, exists := result[profile]; exists {
				return nil, credentialError(ErrProfileConflict, fmt.Sprintf("Legacy data maps more than one account to profile '%s'.", profile))
			}
			result[profile] = legacyEntry(entry)
		}
		return result, nil
	}
	entry := legacyEntry(parsed)
	if len(entry.config) > 0 || len(entry.credentials) > 0 {
		result["default"] = entry
	}
	return result, nil
}

func copyValues(values map[string]string) map[string]string {
	copied := make(map[string]string, len(values))
	for key, value := range values {
		copied[key] = value
	}
	return copied
}

func (store *profileStore) migrateLegacyProfiles(ctx context.Context) error {
	store.migrationMu.Lock()
	defer store.migrationMu.Unlock()
	if store.migrated {
		return nil
	}
	release, err := store.acquireLock(ctx)
	if err != nil {
		return err
	}
	defer release()

	canonicalConfig, err := readINIFile(store.paths.ConfigFile)
	if err != nil {
		return storageError("Credential storage failed while migrating legacy profiles.", err)
	}
	canonicalCredentials, err := readINIFile(store.paths.CredentialsFile)
	if err != nil {
		return storageError("Credential storage failed while migrating legacy profiles.", err)
	}
	legacyConfig := iniData{}
	if store.paths.LegacyConfigFile != store.paths.ConfigFile {
		legacyConfig, err = readINIFile(store.paths.LegacyConfigFile)
		if err != nil {
			return storageError("Credential storage failed while migrating legacy profiles.", err)
		}
	}
	legacyCredentials := iniData{}
	if store.paths.LegacyCredentialsFile != store.paths.CredentialsFile {
		legacyCredentials, err = readINIFile(store.paths.LegacyCredentialsFile)
		if err != nil {
			return storageError("Credential storage failed while migrating legacy profiles.", err)
		}
	}
	legacyJSON, err := readLegacyJSON(store.paths.LegacyJSONFile)
	if err != nil {
		return storageError("Credential storage failed while migrating legacy profiles.", err)
	}
	migrationFile := store.paths.CredentialsFile + ".migrated"
	migratedProfiles, err := readMigrationMarker(migrationFile)
	if err != nil {
		return storageError("Credential storage failed while migrating legacy profiles.", err)
	}
	profiles := map[string]bool{}
	for profile := range legacyConfig {
		profiles[profile] = true
	}
	for profile := range legacyCredentials {
		profiles[profile] = true
	}
	for profile := range legacyJSON {
		profiles[profile] = true
	}
	configChanged := false
	credentialsChanged := false
	markerChanged := false
	for profile := range profiles {
		if err := validateSelectableProfileName(profile); err != nil {
			return err
		}
		if migratedProfiles[profile] {
			continue
		}
		migratedProfiles[profile] = true
		markerChanged = true
		if _, exists := canonicalConfig[profile]; exists {
			continue
		}
		if _, exists := canonicalCredentials[profile]; exists {
			continue
		}
		config := legacyConfig[profile]
		credentials := legacyCredentials[profile]
		if jsonProfile, exists := legacyJSON[profile]; exists {
			if config == nil {
				config = jsonProfile.config
			}
			if credentials == nil {
				credentials = jsonProfile.credentials
			}
		}
		if len(config) > 0 {
			canonicalConfig[profile] = copyValues(config)
			configChanged = true
		}
		if len(credentials) > 0 {
			canonicalCredentials[profile] = copyValues(credentials)
			credentialsChanged = true
		}
	}
	if configChanged {
		if err := atomicWriteINI(store.paths.ConfigFile, canonicalConfig); err != nil {
			return storageError("Credential storage failed while migrating legacy profiles.", err)
		}
	}
	if credentialsChanged {
		if err := atomicWriteINI(store.paths.CredentialsFile, canonicalCredentials); err != nil {
			return storageError("Credential storage failed while migrating legacy profiles.", err)
		}
	}
	if markerChanged {
		if err := writeMigrationMarker(migrationFile, migratedProfiles); err != nil {
			return storageError("Credential storage failed while migrating legacy profiles.", err)
		}
	}
	for _, path := range []string{store.paths.ConfigFile, store.paths.CredentialsFile, migrationFile} {
		if _, statErr := os.Stat(path); statErr == nil {
			if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
				return storageError("Credential storage failed while migrating legacy profiles.", chmodErr)
			}
			if directoryErr := ensureDirectory(filepath.Dir(path)); directoryErr != nil {
				return storageError("Credential storage failed while migrating legacy profiles.", directoryErr)
			}
		}
	}
	store.migrated = true
	return nil
}

func (store *profileStore) readRawProfile(ctx context.Context, profile string) (rawProfile, error) {
	if err := validateSelectableProfileName(profile); err != nil {
		return rawProfile{}, err
	}
	if err := store.migrateLegacyProfiles(ctx); err != nil {
		return rawProfile{}, err
	}
	return store.readRawProfileWithoutMigration(profile)
}

func (store *profileStore) readRawProfileWithoutMigration(profile string) (rawProfile, error) {
	configData, err := readINIFile(store.paths.ConfigFile)
	if err != nil {
		return rawProfile{}, storageError("Credential storage failed while reading a profile.", err)
	}
	credentialsData, err := readINIFile(store.paths.CredentialsFile)
	if err != nil {
		return rawProfile{}, storageError("Credential storage failed while reading a profile.", err)
	}
	config := configData[profile]
	if config == nil {
		config = map[string]string{}
	}
	credentialValues := credentialsData[profile]
	if credentialValues == nil {
		credentialValues = map[string]string{}
	}
	return rawProfile{
		name:        profile,
		config:      config,
		credentials: credentialValues,
		exists:      len(config) > 0 || len(credentialValues) > 0,
	}, nil
}

func (store *profileStore) readProfile(ctx context.Context, profile string) (*StoredProfile, error) {
	raw, err := store.readRawProfile(ctx, profile)
	if err != nil {
		return nil, err
	}
	if !raw.exists {
		return nil, nil
	}
	return &StoredProfile{
		Name: profile,
		Config: ProfileConfig{
			APIURL:  raw.config["api_url"],
			AuthURL: raw.config["auth_url"],
			Org:     raw.config["org"],
		},
	}, nil
}

func (store *profileStore) updateProfile(ctx context.Context, profile string, update ProfileUpdate) error {
	if err := validateSelectableProfileName(profile); err != nil {
		return err
	}
	if err := store.migrateLegacyProfiles(ctx); err != nil {
		return err
	}
	release, err := store.acquireLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	configData, err := readINIFile(store.paths.ConfigFile)
	if err != nil {
		return storageError("Credential storage failed while updating a profile.", err)
	}
	credentialsData, err := readINIFile(store.paths.CredentialsFile)
	if err != nil {
		return storageError("Credential storage failed while updating a profile.", err)
	}
	if update.Config != nil {
		current := configData[profile]
		if current == nil {
			current = map[string]string{}
		}
		if update.Config.APIURL != "" {
			current["api_url"] = update.Config.APIURL
		}
		if update.Config.AuthURL != "" {
			current["auth_url"] = update.Config.AuthURL
		}
		if update.Config.Org != "" {
			current["org"] = update.Config.Org
		}
		configData[profile] = current
		if err := atomicWriteINI(store.paths.ConfigFile, configData); err != nil {
			return storageError("Credential storage failed while updating a profile.", err)
		}
	}
	if update.Credentials != nil {
		if update.Credentials.APIKey != "" {
			credentialsData[profile] = map[string]string{"api_key": update.Credentials.APIKey}
		} else {
			credentialsData[profile] = map[string]string{"access_token": update.Credentials.AccessToken}
			if update.Credentials.RefreshToken != "" {
				credentialsData[profile]["refresh_token"] = update.Credentials.RefreshToken
			}
		}
		if err := atomicWriteINI(store.paths.CredentialsFile, credentialsData); err != nil {
			return storageError("Credential storage failed while updating a profile.", err)
		}
	}
	return nil
}

func (store *profileStore) replaceOAuthCredentials(profile, accessToken, refreshToken string) error {
	if err := validateSelectableProfileName(profile); err != nil {
		return err
	}
	credentialsData, err := readINIFile(store.paths.CredentialsFile)
	if err != nil {
		return storageError("Credential storage failed while persisting refreshed credentials.", err)
	}
	credentialsData[profile] = map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}
	if err := atomicWriteINI(store.paths.CredentialsFile, credentialsData); err != nil {
		return storageError("Credential storage failed while persisting refreshed credentials.", err)
	}
	return nil
}

func (store *profileStore) deleteProfile(ctx context.Context, profile string) error {
	if err := validateSelectableProfileName(profile); err != nil {
		return err
	}
	if err := store.migrateLegacyProfiles(ctx); err != nil {
		return err
	}
	release, err := store.acquireLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	configData, err := readINIFile(store.paths.ConfigFile)
	if err != nil {
		return storageError("Credential storage failed while deleting a profile.", err)
	}
	credentialsData, err := readINIFile(store.paths.CredentialsFile)
	if err != nil {
		return storageError("Credential storage failed while deleting a profile.", err)
	}
	if configData[metadataSection][currentProfileKey] == profile {
		delete(configData[metadataSection], currentProfileKey)
		if len(configData[metadataSection]) == 0 {
			delete(configData, metadataSection)
		}
	}
	delete(configData, profile)
	delete(credentialsData, profile)
	if err := atomicWriteINI(store.paths.ConfigFile, configData); err != nil {
		return storageError("Credential storage failed while deleting a profile.", err)
	}
	if err := atomicWriteINI(store.paths.CredentialsFile, credentialsData); err != nil {
		return storageError("Credential storage failed while deleting a profile.", err)
	}
	return nil
}

func (store *profileStore) clearProfiles(ctx context.Context) error {
	if err := store.migrateLegacyProfiles(ctx); err != nil {
		return err
	}
	release, err := store.acquireLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err := atomicWriteINI(store.paths.ConfigFile, iniData{}); err != nil {
		return storageError("Credential storage failed while clearing profiles.", err)
	}
	if err := atomicWriteINI(store.paths.CredentialsFile, iniData{}); err != nil {
		return storageError("Credential storage failed while clearing profiles.", err)
	}
	return nil
}

func (store *profileStore) readCurrentProfile(ctx context.Context) (string, bool, error) {
	if err := store.migrateLegacyProfiles(ctx); err != nil {
		return "", false, err
	}
	configData, err := readINIFile(store.paths.ConfigFile)
	if err != nil {
		return "", false, storageError("Credential storage failed while reading the current profile.", err)
	}
	metadata := configData[metadataSection]
	if metadata == nil {
		return "", false, nil
	}
	for key := range metadata {
		if key != currentProfileKey {
			return "", false, credentialError(ErrInvalidCredential, fmt.Sprintf("Shared config metadata contains an unsupported '%s' field.", key))
		}
	}
	profile := metadata[currentProfileKey]
	if profile == "" {
		return "", false, nil
	}
	if err := validateSelectableProfileName(profile); err != nil {
		return "", false, err
	}
	return profile, true, nil
}

func (store *profileStore) setCurrentProfile(ctx context.Context, profile string) error {
	if err := validateSelectableProfileName(profile); err != nil {
		return err
	}
	if err := store.migrateLegacyProfiles(ctx); err != nil {
		return err
	}
	release, err := store.acquireLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	configData, err := readINIFile(store.paths.ConfigFile)
	if err != nil {
		return storageError("Credential storage failed while setting the current profile.", err)
	}
	credentialsData, err := readINIFile(store.paths.CredentialsFile)
	if err != nil {
		return storageError("Credential storage failed while setting the current profile.", err)
	}
	if len(credentialsData[profile]) == 0 {
		return credentialError(ErrCredentialNotFound, fmt.Sprintf("Cannot select missing credential profile '%s'.", profile))
	}
	configData[metadataSection] = map[string]string{currentProfileKey: profile}
	if err := atomicWriteINI(store.paths.ConfigFile, configData); err != nil {
		return storageError("Credential storage failed while setting the current profile.", err)
	}
	return nil
}
