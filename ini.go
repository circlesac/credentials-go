package credentials

import (
	"bufio"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type iniData map[string]map[string]string

var (
	profileNamePattern  = regexp.MustCompile(`^[A-Za-z0-9._+@:-]+$`)
	organizationPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	iniKeyPattern       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
)

func validateProfileName(profile string) error {
	if !profileNamePattern.MatchString(profile) {
		return credentialError(ErrInvalidCredential, "Profile names may contain only letters, digits, '.', '_', '-', '+', '@', and ':'.")
	}
	return nil
}

func validateSelectableProfileName(profile string) error {
	if err := validateProfileName(profile); err != nil {
		return err
	}
	if profile == "__circles__" {
		return credentialError(ErrInvalidCredential, "Profile name '__circles__' is reserved for shared configuration metadata.")
	}
	return nil
}

func parseINI(contents string) (iniData, error) {
	data := iniData{}
	var section string
	scanner := bufio.NewScanner(strings.NewReader(contents))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") && strings.Count(line, "[") == 1 && strings.Count(line, "]") == 1 {
			section = line[1 : len(line)-1]
			if err := validateProfileName(section); err != nil {
				return nil, err
			}
			if _, exists := data[section]; exists {
				return nil, credentialError(ErrProfileConflict, fmt.Sprintf("Profile '%s' is declared more than once.", section))
			}
			data[section] = map[string]string{}
			continue
		}
		separator := strings.Index(line, "=")
		if section == "" || separator <= 0 {
			return nil, credentialError(ErrInvalidCredential, fmt.Sprintf("Invalid INI syntax at line %d.", lineNumber))
		}
		key := strings.TrimSpace(line[:separator])
		value := strings.TrimSpace(line[separator+1:])
		if !iniKeyPattern.MatchString(key) || value == "" {
			return nil, credentialError(ErrInvalidCredential, fmt.Sprintf("Invalid INI entry at line %d.", lineNumber))
		}
		if _, exists := data[section][key]; exists {
			return nil, credentialError(ErrProfileConflict, fmt.Sprintf("Profile '%s' contains duplicate '%s' entries.", section, key))
		}
		data[section][key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

func serializeINI(data iniData) (string, error) {
	sections := make([]string, 0, len(data))
	for section, entries := range data {
		if len(entries) > 0 {
			sections = append(sections, section)
		}
	}
	sort.Strings(sections)
	var builder strings.Builder
	for sectionIndex, section := range sections {
		if err := validateProfileName(section); err != nil {
			return "", err
		}
		if sectionIndex > 0 {
			builder.WriteString("\n")
		}
		builder.WriteString("[")
		builder.WriteString(section)
		builder.WriteString("]\n")
		keys := make([]string, 0, len(data[section]))
		for key := range data[section] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			builder.WriteString(key)
			builder.WriteString(" = ")
			builder.WriteString(data[section][key])
			builder.WriteString("\n")
		}
	}
	return builder.String(), nil
}
