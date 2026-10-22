//go:build !windows

package osutil

// systemPathEntries has no persistent store outside Windows: the client sends
// the PATH that VS Code resolved from the login shell.
func systemPathEntries() []string { return nil }
