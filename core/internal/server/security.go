package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"compliance/internal/osutil"
)

var (
	ErrUnauthorized       = errors.New("authentification requise ou jeton Bearer invalide")
	ErrForbiddenHost      = errors.New("en-tête Host non autorisé (rejet DNS Rebinding)")
	ErrForbiddenOrigin    = errors.New("en-tête Origin externe ou non autorisé (rejet CSRF)")
	ErrWorkspaceUntrusted = errors.New("répertoire cible hors périmètre des espaces autorisés")
)

// GenerateBearerToken generates a cryptographically secure 256-bit token (64 hex chars).
func GenerateBearerToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("génération du jeton cryptographique aléatoire: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// WriteProtectedToken writes token to path with POSIX 0600 or Windows ACL.
func WriteProtectedToken(path string, token string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("création du dossier du jeton: %w", err)
	}

	// Write file with 0600
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		return fmt.Errorf("écriture du fichier de jeton: %w", err)
	}

	// On Windows, enforce ACL with icacls using current user SID to restrict to current user only
	if runtime.GOOS == "windows" {
		grantTarget := ""
		if u, err := user.Current(); err == nil && u.Uid != "" {
			grantTarget = fmt.Sprintf("*%s:(F)", u.Uid)
		} else if username := os.Getenv("USERNAME"); username != "" {
			grantTarget = fmt.Sprintf("%s:(F)", username)
		}
		if grantTarget != "" {
			cmd := exec.Command("icacls", path, "/inheritance:r", "/grant:r", grantTarget)
			osutil.SetHideWindow(cmd)
			_ = cmd.Run() // Best effort on Windows environments
		}
	}

	return nil
}

// SecurityManager enforces authentication, host validation, origin checks, and workspace paths.
type SecurityManager struct {
	Token              string
	Port               int
	ApprovedWorkspaces []string
}

// NewSecurityManager creates a new SecurityManager.
func NewSecurityManager(token string, port int, approvedWorkspaces []string) *SecurityManager {
	canonicalWorkspaces := make([]string, 0, len(approvedWorkspaces))
	for _, ws := range approvedWorkspaces {
		c, err := CanonicalizePath(ws)
		if err == nil {
			canonicalWorkspaces = append(canonicalWorkspaces, c)
		}
	}
	return &SecurityManager{
		Token:              token,
		Port:               port,
		ApprovedWorkspaces: canonicalWorkspaces,
	}
}

// ValidateHost checks if the Host header corresponds to 127.0.0.1 or localhost on the expected port.
func (sm *SecurityManager) ValidateHost(hostHeader string) bool {
	if hostHeader == "" {
		return false
	}
	// Extract host and port
	host, port, err := net.SplitHostPort(hostHeader)
	if err != nil {
		// Might not have port if default, but local daemon always uses specific port
		host = hostHeader
		port = ""
	}

	// If port is present, verify port match
	if port != "" && sm.Port > 0 {
		expectedPort := fmt.Sprintf("%d", sm.Port)
		if port != expectedPort {
			return false
		}
	}

	// Host must be 127.0.0.1, [::1] or localhost
	h := strings.ToLower(host)
	return h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "[::1]"
}

// ValidateOrigin validates the Origin header.
// If Origin is absent, request is treated as local CLI / Node native request and allowed.
// If Origin is present, it must be from an authorized origin (localhost/127.0.0.1 matching port, vscode-file://, or "null").
func (sm *SecurityManager) ValidateOrigin(originHeader string) bool {
	if originHeader == "" {
		// Native client (Node.js http, curl, etc.)
		return true
	}

	trimmed := strings.TrimSpace(originHeader)
	if trimmed == "null" {
		return true
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return false
	}

	// VS Code webview origins use vscode-webview:// or vscode-file:// schemes
	if parsed.Scheme == "vscode-webview" || parsed.Scheme == "vscode-file" {
		return true
	}

	// Local HTTP origin: scheme must be http, host must match localhost/127.0.0.1/::1, port must match daemon port
	if parsed.Scheme == "http" {
		hostname := strings.ToLower(parsed.Hostname())
		if hostname != "127.0.0.1" && hostname != "localhost" && hostname != "::1" {
			return false
		}
		port := parsed.Port()
		if sm.Port > 0 {
			expectedPort := fmt.Sprintf("%d", sm.Port)
			if port != expectedPort {
				return false
			}
		}
		// According to RFC 6454, serialized Origin header has no path or query
		if parsed.Path != "" && parsed.Path != "/" {
			return false
		}
		return true
	}

	return false
}

// ValidateToken verifies the Authorization header contains the valid Bearer token.
func (sm *SecurityManager) ValidateToken(authHeader string) bool {
	if authHeader == "" {
		return false
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return false
	}
	providedToken := strings.TrimSpace(parts[1])
	// Constant-time comparison
	return subtle.ConstantTimeCompare([]byte(providedToken), []byte(sm.Token)) == 1
}

// AddApprovedWorkspace registers a new approved workspace root.
func (sm *SecurityManager) AddApprovedWorkspace(wsPath string) error {
	c, err := CanonicalizePath(wsPath)
	if err != nil {
		return err
	}
	for _, existing := range sm.ApprovedWorkspaces {
		if strings.EqualFold(existing, c) {
			return nil
		}
	}
	sm.ApprovedWorkspaces = append(sm.ApprovedWorkspaces, c)
	return nil
}

// ValidateTargetPath resolves symlinks and verifies the path belongs to an approved workspace.
func (sm *SecurityManager) ValidateTargetPath(targetPath string) (string, error) {
	if targetPath == "" {
		return "", errors.New("le chemin cible ne peut pas être vide")
	}

	canonicalTarget, err := CanonicalizePath(targetPath)
	if err != nil {
		return "", fmt.Errorf("résolution du chemin cible impossible (%s): %w", targetPath, err)
	}

	fi, err := os.Stat(canonicalTarget)
	if err != nil {
		return "", fmt.Errorf("chemin cible introuvable: %w", err)
	}
	if !fi.IsDir() {
		return "", errors.New("le chemin cible doit être un répertoire")
	}

	// Verify target is within at least one approved workspace
	if len(sm.ApprovedWorkspaces) == 0 {
		// If no workspaces explicitly configured, require that target itself is explicitly registered
		return "", ErrWorkspaceUntrusted
	}

	targetLower := strings.ToLower(canonicalTarget)
	for _, ws := range sm.ApprovedWorkspaces {
		wsLower := strings.ToLower(ws)
		if targetLower == wsLower || strings.HasPrefix(targetLower, wsLower+string(filepath.Separator)) {
			return canonicalTarget, nil
		}
	}

	return "", fmt.Errorf("%w: %s n'appartient à aucun workspace approuvé", ErrWorkspaceUntrusted, targetPath)
}

// CanonicalizePath cleans path and resolves all symlinks.
func CanonicalizePath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// If path doesn't exist yet, return cleaned abs
		if os.IsNotExist(err) {
			return filepath.Clean(abs), nil
		}
		return "", err
	}
	return filepath.Clean(real), nil
}

// Middleware creates an HTTP handler middleware enforcing Host, Origin, and Bearer authentication.
func (sm *SecurityManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Validate Host header
		if !sm.ValidateHost(r.Host) {
			http.Error(w, "Forbidden: invalid Host header", http.StatusForbidden)
			return
		}

		// 2. Validate Origin header if present
		origin := r.Header.Get("Origin")
		if origin != "" && !sm.ValidateOrigin(origin) {
			http.Error(w, "Forbidden: untrusted Origin header", http.StatusForbidden)
			return
		}

		// 3. Validate Bearer Token
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "Unauthorized: missing Authorization header", http.StatusUnauthorized)
			return
		}
		if !sm.ValidateToken(auth) {
			http.Error(w, "Forbidden: invalid Bearer token", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
