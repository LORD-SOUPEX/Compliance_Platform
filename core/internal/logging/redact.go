package logging

import (
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Masked replaces a secret in logs, events and invocation records.
const Masked = "<masqué>"

var (
	sensitiveKey = regexp.MustCompile(`(?i)(TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIAL|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|AUTHORIZATION|(^|_)AUTH($|_))`)
	urlUserinfo  = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@`)
)

// SensitiveKey reports environment variable or flag names that carry secrets.
func SensitiveKey(key string) bool {
	return sensitiveKey.MatchString(strings.TrimLeft(key, "-"))
}

// RedactText removes credentials embedded in URLs (proxy, registry mirror).
func RedactText(value string) string {
	return urlUserinfo.ReplaceAllString(value, "${1}"+Masked+"@")
}

// RedactEnvValue masks the value of a sensitive variable and URL credentials elsewhere.
func RedactEnvValue(key, value string) string {
	if SensitiveKey(key) {
		return Masked
	}
	return RedactText(value)
}

// RedactArgs masks "-flag=value" and "-flag value" pairs whose flag name is sensitive.
func RedactArgs(args []string) []string {
	out := make([]string, len(args))
	maskNext := false
	for i, arg := range args {
		if maskNext {
			out[i] = Masked
			maskNext = false
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if name, _, found := strings.Cut(arg, "="); found {
				if SensitiveKey(name) {
					out[i] = name + "=" + Masked
					continue
				}
			} else if SensitiveKey(arg) {
				out[i] = arg
				maskNext = true
				continue
			}
		}
		out[i] = RedactText(arg)
	}
	return out
}

// EnvDiff compares a child environment with the daemon's own. It returns the
// variables that are new or changed (values redacted) and the names removed.
// Windows variable names are case-insensitive (Path and PATH are one variable).
func EnvDiff(base, child []string) (map[string]string, []string) {
	fold := func(key string) string {
		if runtime.GOOS == "windows" {
			return strings.ToUpper(key)
		}
		return key
	}
	parse := func(entries []string) (map[string]string, map[string]string) {
		values := make(map[string]string, len(entries))
		names := make(map[string]string, len(entries))
		for _, entry := range entries {
			key, value, ok := strings.Cut(entry, "=")
			if !ok || key == "" {
				continue
			}
			values[fold(key)] = value
			names[fold(key)] = key
		}
		return values, names
	}
	baseValues, baseNames := parse(base)
	childValues, childNames := parse(child)
	added := map[string]string{}
	for key, value := range childValues {
		if previous, ok := baseValues[key]; !ok || previous != value {
			added[childNames[key]] = RedactEnvValue(key, value)
		}
	}
	var removed []string
	for key := range baseValues {
		if _, ok := childValues[key]; !ok {
			removed = append(removed, baseNames[key])
		}
	}
	sort.Strings(removed)
	return added, removed
}
