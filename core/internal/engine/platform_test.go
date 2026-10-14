package engine

import "testing"

func TestPlatformSupported(t *testing.T) {
	if !platformSupported(nil, "macos-arm64") {
		t.Fatal("an empty support list does not restrict the platform")
	}
	if !platformSupported([]string{"macos-x64", "macos-arm64"}, "macos-arm64") {
		t.Fatal("declared platform should be supported")
	}
	if platformSupported([]string{"linux-x64", "macos-arm64"}, "macos-x64") {
		t.Fatal("macos-x64 should be rejected when it is absent from platform_support")
	}
	if !platformSupported([]string{"windows-x64"}, "") {
		t.Fatal("an empty platform id skips the filter")
	}
}

func TestPowershellHostDoesNotUseWindowsPowerShellOnDarwin(t *testing.T) {
	got := powershellHost("darwin", "/opt/compliance/PSScriptAnalyzer.psd1")
	if got == "powershell.exe" {
		t.Fatal("darwin must not fall back to powershell.exe")
	}
	if got != "pwsh" && !hasSuffixFold(got, "pwsh") {
		t.Fatalf("powershellHost(darwin) = %q, want pwsh", got)
	}

	windows := powershellHost("windows", "/opt/compliance/PSScriptAnalyzer.psd1")
	if windows != "powershell.exe" {
		t.Fatalf("powershellHost(windows) = %q, want powershell.exe", windows)
	}
}

func hasSuffixFold(value, suffix string) bool {
	if len(value) < len(suffix) {
		return false
	}
	return value[len(value)-len(suffix):] == suffix
}
