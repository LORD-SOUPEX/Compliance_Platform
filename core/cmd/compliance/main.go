package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"compliance/internal/discovery"
	"compliance/internal/distribution"
	"compliance/internal/embedded"
	"compliance/internal/engine"
	"compliance/internal/logging"
	"compliance/internal/osutil"
	"compliance/internal/report"
	"compliance/internal/selftest"
	"compliance/internal/server"
	"compliance/internal/sessions"
	engineversion "compliance/internal/version"
)

const version = engineversion.Version

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	command := os.Args[1]
	switch command {
	case "selftest":
		runSelftest(os.Args[2:])
	case "daemon":
		runDaemon(os.Args[2:])
	case "discovery":
		runDiscovery(os.Args[2:])
	case "runtime":
		if len(os.Args) < 3 || (os.Args[2] != "sync" && os.Args[2] != "sign" && os.Args[2] != "verify" && os.Args[2] != "node") {
			fmt.Fprintln(os.Stderr, "Usage: compliance runtime sync | sign | verify | node")
			os.Exit(2)
		}
		if os.Args[2] == "node" {
			runRuntimeNode()
			return
		}
		if os.Args[2] == "verify" {
			runRuntimeVerify(os.Args[3:])
			return
		}
		if os.Args[2] == "sign" {
			runRuntimeSign(os.Args[3:])
			return
		}
		runRuntimeSync(os.Args[3:])
	case "sessions":
		runSessions(os.Args[2:])
	case "run":
		runPipeline(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("compliance %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Sous-commande inconnue: %s\n\n", command)
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Compliance Platform - Cœur Multi-OS

Usage:
  compliance <commande> [arguments]

Sous-commandes disponibles:
  selftest [options]      Exécute la suite complète de validation locale multi-OS
  daemon [options]        Démarre le démon local HTTP/SSE sur 127.0.0.1
  discovery <chemin>      Découvre les sources et racines Python d'un répertoire
  runtime sync [options]  Télécharge et vérifie les outils depuis un manifeste statique signé
  runtime node             Installe eslint et typescript dans ~/.compliance/tools/node
  runtime sign           Signe le manifeste avec une clé privée Ed25519 fournie par -key-file
  sessions purge         Conserve au plus 5 dossiers de session reconnus
  run <chemin> [options]  Exécute le pipeline Python (Ruff + Bandit) et produit le rapport v1

Options globales:
`)
}

func runDaemon(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	listenAddr := fs.String("listen", "127.0.0.1:0", "Adresse d'écoute du démon (boucle locale exclusivement)")
	stateDir := fs.String("state-dir", "", "Répertoire d'état du démon (défaut: ~/.compliance)")
	catalogPath := fs.String("catalog", "", "Chemin vers control-catalog.json")
	platformRoot := fs.String("platform-root", "", "Racine du dépôt Compliance Platform")
	workspacesStr := fs.String("workspaces", "", "Liste de chemins de workspaces approuvés (séparés par des virgules)")
	_ = fs.Parse(args)

	var approvedWorkspaces []string
	if *workspacesStr != "" {
		for _, w := range strings.Split(*workspacesStr, ",") {
			if trimmed := strings.TrimSpace(w); trimmed != "" {
				approvedWorkspaces = append(approvedWorkspaces, trimmed)
			}
		}
	}

	if *platformRoot == "" {
		cwd, _ := os.Getwd()
		*platformRoot = cwd
	}
	bootStarted := time.Now()
	closeLog := setupDaemonLog(*stateDir)
	defer closeLog()
	slog.Info("daemon_starting", "version", version, "pid", os.Getpid(), "os", runtime.GOOS, "arch", runtime.GOARCH,
		"platform", distribution.DetectPlatform(), "state_dir", *stateDir, "platform_root", *platformRoot,
		"path", logging.RedactText(os.Getenv("PATH")))
	// Listen first: the network check of the registry (up to 3 s, more behind a
	// slow proxy) runs once the daemon answers, so the first client never waits on it.
	catalogForced := strings.TrimSpace(*catalogPath) != ""
	selection := distribution.RefreshRegistry(context.Background(), distribution.RefreshOptions{
		LocalRoot: *platformRoot,
		Offline:   true,
	})
	slog.Info("registry_selected", "source", selection.Source, "manifest", selection.ManifestPath, "catalog", selection.CatalogPath, "network", false)
	if !catalogForced && selection.Source != "local" && selection.CatalogPath != "" {
		*catalogPath = selection.CatalogPath
	}
	resolvedCatalog, err := embedded.ResolveAsset("control-catalog.json", *catalogPath, filepath.Join(*platformRoot, ".config", "control-catalog.json"))
	if err != nil {
		slog.Error("catalog_missing", "err", err)
		fmt.Fprintf(os.Stderr, "[ERROR] Catalogue de contrôles introuvable: %v\n", err)
		closeLog()
		os.Exit(1)
	}
	*catalogPath = resolvedCatalog

	srv, err := server.StartDaemon(server.DaemonConfig{
		ListenAddr:         *listenAddr,
		StateDir:           *stateDir,
		ApprovedWorkspaces: approvedWorkspaces,
		CatalogPath:        *catalogPath,
		PlatformRoot:       *platformRoot,
		Version:            version,
	})
	if err != nil {
		code := 1
		if errors.Is(err, server.ErrDaemonAlreadyRunning) {
			code = server.ExitAlreadyRunning
		}
		slog.Error("daemon_start_failed", "err", err, "exit_code", code, "duration_ms", time.Since(bootStarted).Milliseconds())
		fmt.Fprintf(os.Stderr, "[ERROR] Échec de démarrage du démon: %v\n", err)
		closeLog()
		os.Exit(code)
	}

	slog.Info("daemon_ready", "url", srv.URL(), "catalog", *catalogPath, "duration_ms", time.Since(bootStarted).Milliseconds())
	fmt.Printf("[INFO] Démon compliance démarré sur %s (PID %d)\n", srv.URL(), os.Getpid())
	fmt.Printf("[INFO] Jeton Bearer généré et protégé avec succès\n")
	srv.SetRegistry(registryInfo(selection, true))
	go refreshRegistryInBackground(srv, *platformRoot, catalogForced)
	srv.WatchIdle(server.IdleTimeout())

	// Intercept termination signals; /shutdown and the idle watch close Done().
	sigCh := make(chan os.Signal, 1)
	osutil.NotifyTermination(sigCh)
	select {
	case <-sigCh:
	case <-srv.Done():
	}

	fmt.Println("\n[INFO] Arrêt du démon compliance en cours...")
	slog.Info("daemon_stopping")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Close(ctx)
	fmt.Println("[INFO] Démon arrêté proprement.")
	slog.Info("daemon_stopped")
	closeLog()
	os.Exit(0)
}

func registryInfo(selection distribution.RegistrySelection, refreshing bool) server.RegistryInfo {
	return server.RegistryInfo{
		Source:       selection.Source,
		ManifestPath: selection.ManifestPath,
		CatalogPath:  selection.CatalogPath,
		SigPath:      selection.SigPath,
		RegistryURL:  logging.RedactText(selection.RegistryURL),
		Refreshing:   refreshing,
	}
}

// refreshRegistryInBackground checks the remote registry, switches the catalog
// when a newer one was cached, then upgrades installed tools under the
// exclusive tools lock (audits in progress finish first).
func refreshRegistryInBackground(srv *server.DaemonServer, platformRoot string, catalogForced bool) {
	started := time.Now()
	selection := distribution.RefreshRegistry(context.Background(), distribution.RefreshOptions{
		LocalRoot: platformRoot,
		Timeout:   3 * time.Second,
	})
	slog.Info("registry_selected", "source", selection.Source, "manifest", selection.ManifestPath, "catalog", selection.CatalogPath,
		"registry_url", logging.RedactText(selection.RegistryURL), "network", true, "duration_ms", time.Since(started).Milliseconds())
	srv.SetRegistry(registryInfo(selection, false))
	if !catalogForced && selection.Source == "remote" {
		srv.SetCatalogPath(selection.CatalogPath)
	}
	distribution.UpgradeInstalledTools(distribution.UpgradeOptions{
		ManifestPath: selection.ManifestPath,
		BaselinePath: filepath.Join(platformRoot, ".config", "runtime-manifest.json"),
		SigPath:      selection.SigPath,
		CacheDir:     defaultCacheDir(),
		RegistryURL:  selection.RegistryURL,
		OnUpgrade:    srv.SetToolUpgrading,
	})
}

// setupDaemonLog writes the JSON journal to <state-dir>/logs/daemon.log.
// COMPLIANCE_LOG_LEVEL selects trace, debug (default), info, warn or error.
// Without a writable folder the daemon keeps running with the stderr logger.
func setupDaemonLog(stateDir string) func() {
	if stateDir == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			stateDir = filepath.Join(home, ".compliance")
		} else {
			stateDir = ".compliance"
		}
	}
	closeLog, err := logging.Setup(logging.Options{
		Dir:   filepath.Join(stateDir, "logs"),
		Level: logging.ParseLevel(os.Getenv("COMPLIANCE_LOG_LEVEL")),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Journal du démon indisponible : %v\n", err)
		return func() {}
	}
	return closeLog
}

func runDiscovery(args []string) {
	fs := flag.NewFlagSet("discovery", flag.ExitOnError)
	repo := fs.String("repo", "", "Répertoire cible à analyser")
	indent := fs.Bool("indent", true, "Formater la sortie JSON")
	_ = fs.Parse(reorderFlags(args))

	target := "."
	if *repo != "" {
		target = *repo
	} else if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	absTarget, err := osutil.CanonicalPath(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Chemin invalide: %v\n", err)
		os.Exit(2)
	}

	res, err := discovery.DiscoverAll(absTarget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Erreur de découverte: %v\n", err)
		os.Exit(2)
	}

	jsonBytes, err := res.ToJSON(*indent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Sérialisation JSON: %v\n", err)
		os.Exit(2)
	}

	fmt.Println(string(jsonBytes))
	os.Exit(0)
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func runSessions(args []string) {
	if len(args) == 0 || (args[0] != "purge" && args[0] != "resolve") {
		fmt.Fprintln(os.Stderr, "Usage: compliance sessions purge|resolve")
		os.Exit(2)
	}
	if args[0] == "resolve" {
		fs := flag.NewFlagSet("sessions resolve", flag.ExitOnError)
		chosen := fs.String("path", "", "Dossier demandé")
		var forbid multiFlag
		fs.Var(&forbid, "forbid", "Dossier interdit")
		_ = fs.Parse(args[1:])
		resolved, err := sessions.ResolveSessionRoot(*chosen, []string(forbid))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
			os.Exit(1)
		}
		fmt.Println(resolved)
		return
	}
	fs := flag.NewFlagSet("sessions purge", flag.ExitOnError)
	root := fs.String("root", "", "Dossier des runs de session")
	keep := fs.Int("keep", sessions.DefaultKeep, "Nombre de sessions conservées (1 à 1000)")
	reserve := fs.Int("reserve", 0, "Places réservées pour une session imminente")
	var protect multiFlag
	fs.Var(&protect, "protect", "Nom de dossier à conserver")
	_ = fs.Parse(args[1:])
	if strings.TrimSpace(*root) == "" {
		fmt.Fprintln(os.Stderr, "[ERROR] sessions purge: -root est obligatoire")
		os.Exit(2)
	}
	result, err := sessions.Purge(*root, sessions.Options{Keep: *keep, Reserve: *reserve, Protect: []string(protect)})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] purge: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(sessions.Summary(result))
}

func runRuntimeVerify(args []string) {
	fs := flag.NewFlagSet("runtime verify", flag.ExitOnError)
	manifestPath := fs.String("manifest", ".config/runtime-manifest.json", "Manifeste")
	sigPath := fs.String("sig", ".config/runtime-manifest.json.sig", "Signature hexadécimale")
	_ = fs.Parse(args)
	resolvedManifest, err := embedded.ResolveAsset("runtime-manifest.json", *manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Manifeste introuvable: %v\n", err)
		os.Exit(1)
	}
	body, err := os.ReadFile(resolvedManifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Lecture du manifeste: %v\n", err)
		os.Exit(1)
	}
	resolvedSig, sigErr := embedded.ResolveAsset("runtime-manifest.json.sig", *sigPath)
	if sigErr != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Signature absente : %v\n", sigErr)
		fmt.Println("[PASS] Manifeste accepté sans signature.")
		return
	}
	sig, err := os.ReadFile(resolvedSig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Signature illisible : %v\n", err)
		fmt.Println("[PASS] Manifeste accepté sans signature.")
		return
	}
	pub, err := hex.DecodeString(distribution.DefaultPhase0PublicKeyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Clé publique: %v\n", err)
		os.Exit(1)
	}
	if err := distribution.VerifyManifest(body, string(sig), ed25519.PublicKey(pub)); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Signature absente ou différente : %v\n", err)
		fmt.Println("[PASS] Manifeste accepté sans bloquer sur la signature.")
		return
	}
	fmt.Println("[PASS] Signature du manifeste valide.")
}

func runRuntimeSign(args []string) {
	fs := flag.NewFlagSet("runtime sign", flag.ExitOnError)
	manifestPath := fs.String("manifest", ".config/runtime-manifest.json", "Manifeste à signer")
	keyFile := fs.String("key-file", "", "Clé privée Ed25519 hexadécimale (seed 32 octets ou clé 64 octets)")
	out := fs.String("out", ".config/runtime-manifest.json.sig", "Fichier de signature hexadécimale")
	_ = fs.Parse(args)
	if strings.TrimSpace(*keyFile) == "" {
		fmt.Fprintln(os.Stderr, "[ERROR] runtime sign: -key-file est obligatoire. La clé privée n'est pas dans le dépôt.")
		os.Exit(2)
	}
	body, err := os.ReadFile(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] manifeste illisible: %v\n", err)
		os.Exit(2)
	}
	keyText, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] clé illisible: %v\n", err)
		os.Exit(2)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(keyText)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] clé privée non hexadécimale: %v\n", err)
		os.Exit(2)
	}
	var private ed25519.PrivateKey
	switch len(raw) {
	case ed25519.SeedSize:
		private = ed25519.NewKeyFromSeed(raw)
	case ed25519.PrivateKeySize:
		private = ed25519.PrivateKey(raw)
	default:
		fmt.Fprintln(os.Stderr, "[ERROR] la clé doit faire 32 octets (seed) ou 64 octets (clé privée)")
		os.Exit(2)
	}
	if err := os.WriteFile(*out, []byte(distribution.SignManifest(body, private)), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] écriture de la signature: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[PASS] Signature écrite : %s\n", *out)
}

func runRuntimeSync(args []string) {
	fs := flag.NewFlagSet("runtime sync", flag.ExitOnError)
	manifestPath := fs.String("manifest", ".config/runtime-manifest.json", "Chemin ou URL du manifeste")
	sigPath := fs.String("sig", ".config/runtime-manifest.json.sig", "Chemin ou URL de la signature Ed25519")
	cacheDir := fs.String("cache-dir", defaultCacheDir(), "Dossier local de cache des outils")
	pubKeyHex := fs.String("pubkey", distribution.DefaultPhase0PublicKeyHex, "Clé publique Ed25519 (hex)")
	caBundle := fs.String("ca-bundle", "", "Chemin vers le bundle CA d'entreprise")
	platform := fs.String("platform", distribution.DetectPlatform(), "Plateforme cible")
	toolName := fs.String("tool", "", "N'installer que cet outil du manifeste")
	registryURL := fs.String("registry-url", "", "URL de base personnalisée du registre d'outils")
	registryToken := fs.String("registry-token", "", "Jeton d'authentification Bearer pour le registre (ou COMPLIANCE_REGISTRY_TOKEN)")
	_ = fs.Parse(args)

	pubBytes, err := hex.DecodeString(*pubKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		fmt.Fprintf(os.Stderr, "[ERROR] Clé publique Ed25519 invalide\n")
		os.Exit(2)
	}

	resolvedManifest, err := embedded.ResolveAsset("runtime-manifest.json", *manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Manifeste runtime introuvable: %v\n", err)
		os.Exit(2)
	}
	resolvedSig, sigErr := embedded.ResolveAsset("runtime-manifest.json.sig", *sigPath)
	if sigErr != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Signature absente, installation poursuivie : %v\n", sigErr)
		*sigPath = ""
	} else {
		*sigPath = resolvedSig
	}
	*manifestPath = resolvedManifest

	fmt.Printf("[INFO] Synchronisation runtime pour la plateforme %s...\n", *platform)
	res, err := distribution.SyncRuntime(distribution.SyncOptions{
		ManifestPath:  *manifestPath,
		SigPath:       *sigPath,
		CacheDir:      *cacheDir,
		Platform:      *platform,
		PublicKey:     ed25519.PublicKey(pubBytes),
		CABundlePath:  *caBundle,
		ToolName:      *toolName,
		RegistryURL:   *registryURL,
		RegistryToken: *registryToken,
	})
	if res != nil {
		for name, path := range res.SyncedTools {
			fmt.Printf("  - %s -> %s\n", name, path)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[PASS] Synchronisation réussie pour %s.\n", res.Platform)
	os.Exit(0)
}

func runRuntimeNode() {
	opts := distribution.SyncOptions{
		CacheDir: defaultCacheDir(),
		Platform: distribution.DetectPlatform(),
		ToolName: "node",
	}
	if manifestPath, err := embedded.ResolveAsset("runtime-manifest.json", ".config/runtime-manifest.json"); err == nil {
		opts.ManifestPath = manifestPath
	}
	if sigPath, err := embedded.ResolveAsset("runtime-manifest.json.sig", ".config/runtime-manifest.json.sig"); err == nil {
		opts.SigPath = sigPath
	}
	res, err := distribution.SyncRuntime(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Installation du bundle Node depuis le registre: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[PASS] Bundle Node installé depuis le registre (%s).\n", res.Platform)
}

func runPipeline(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	repo := fs.String("repo", "", "Répertoire cible à auditer")
	outputPath := fs.String("output", "", "Chemin où écrire le rapport JSON (défaut: stdout)")
	reportPath := fs.String("report", "", "Chemin où écrire le rapport JSON (alias pour -output)")
	planOnly := fs.Bool("plan-only", false, "Générer uniquement le plan ordonnancé DAG sans exécuter les contrôles")
	allowCode := fs.Bool("allow-code", false, "Autoriser l'exécution de code")
	allowNetwork := fs.Bool("allow-network", false, "Autoriser les accès réseau")
	timeoutSec := fs.Int("timeout", 300, "Délai maximum par contrôle en secondes")
	platformRootFlag := fs.String("platform-root", "", "Racine du dépôt Compliance Platform")
	catalogFlag := fs.String("catalog", "", "Chemin vers control-catalog.json")
	_ = fs.Parse(reorderFlags(args))

	target := "."
	if *repo != "" {
		target = *repo
	} else if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	absTarget, err := osutil.CanonicalPath(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Chemin invalide: %v\n", err)
		os.Exit(2)
	}

	platformRoot := *platformRootFlag
	if platformRoot == "" {
		platformRoot = findPlatformRoot()
	}

	catalogPath, err := embedded.ResolveAsset("control-catalog.json", *catalogFlag, filepath.Join(platformRoot, ".config", "control-catalog.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Catalogue de contrôles introuvable: %v\n", err)
		os.Exit(2)
	}

	outReport := *outputPath
	if outReport == "" {
		outReport = *reportPath
	}

	opts := engine.ComplianceOptions{
		RepoRoot:           absTarget,
		PlatformRoot:       platformRoot,
		CatalogPath:        catalogPath,
		AllowNetwork:       *allowNetwork,
		AllowCodeExecution: *allowCode,
		PlanOnly:           *planOnly,
		TimeoutSeconds:     *timeoutSec,
		SourceAdapter:      "CLI",
		OnControlStart: func(ctrl *engine.PlannedControl) {
			fmt.Fprintf(os.Stderr, "  [%-8s] %s\n", "RUNNING", ctrl.ID)
		},
		OnControlDone: func(ctrl *engine.PlannedControl, res *report.ExecutionResult) {
			fmt.Fprintf(os.Stderr, "  [%-8s] %s (%d ms)\n", strings.ToUpper(res.Status), ctrl.ID, res.DurationMs)
		},
	}

	if *planOnly {
		fmt.Fprintf(os.Stderr, "[INFO] Planification des contrôles (plan-only) sur: %s\n", absTarget)
	} else {
		fmt.Fprintf(os.Stderr, "[INFO] Lancement de l'audit complet Compliance Platform sur: %s\n", absTarget)
	}

	ctx := context.Background()
	// Same contract as the daemon: no installation replaces a tool while this run probes or executes it.
	osutil.RefreshPath("")
	unlock, err := distribution.LockTools(ctx, "", false, "compliance run")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		os.Exit(2)
	}
	rep, err := engine.RunCompliance(ctx, opts)
	unlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Échec de la session de conformité: %v\n", err)
		os.Exit(2)
	}

	jsonBytes, err := rep.ToJSON(true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Sérialisation du rapport: %v\n", err)
		os.Exit(2)
	}

	if outReport != "" {
		dir := filepath.Dir(outReport)
		if dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0755)
		}
		if err := os.WriteFile(outReport, jsonBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Écriture du rapport sur %s: %v\n", outReport, err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "[INFO] Rapport enregistré dans: %s\n", outReport)
	} else {
		fmt.Println(string(jsonBytes))
	}

	if *planOnly {
		fmt.Fprintf(os.Stderr, "\n[PLAN] Plan généré avec succès (%d contrôles planifiés)\n", len(rep.ExecutionPlan.Controls))
		os.Exit(0)
	}

	verdict := "UNKNOWN"
	if rep.Verdict != nil {
		verdict = *rep.Verdict
	}
	fmt.Fprintf(os.Stderr, "\n[VERDICT CONSULTATIF] %s (Success: %d, Fail: %d, Error: %d, Skipped: %d)\n",
		verdict, rep.Summary.Success, rep.Summary.Fail, rep.Summary.Error, rep.Summary.Skipped)

	if verdict == "PASS" {
		os.Exit(0)
	}
	os.Exit(1)
}

func findPlatformRoot() string {
	cwd, _ := os.Getwd()
	curr := cwd
	for {
		if _, err := os.Stat(filepath.Join(curr, ".config", "control-catalog.json")); err == nil {
			return curr
		}
		parent := filepath.Dir(curr)
		if parent == curr {
			break
		}
		curr = parent
	}
	exe, err := os.Executable()
	if err == nil {
		curr = filepath.Dir(exe)
		for {
			if _, err := os.Stat(filepath.Join(curr, ".config", "control-catalog.json")); err == nil {
				return curr
			}
			parent := filepath.Dir(curr)
			if parent == curr {
				break
			}
			curr = parent
		}
	}
	return cwd
}

func defaultCacheDir() string {
	return osutil.DefaultToolCacheDir()
}

type ToolInvocation struct {
	Executable string
	Args       []string
	Env        []string
}

func isBoolFlag(arg string) bool {
	clean := strings.TrimLeft(arg, "-")
	switch clean {
	case "plan-only", "allow-code", "allow-network", "indent", "confirm_apply_destroy":
		return true
	default:
		return false
	}
}

func reorderFlags(args []string) []string {
	var flags []string
	var pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if !strings.Contains(arg, "=") && !isBoolFlag(arg) && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flags = append(flags, args[i])
			}
		} else {
			pos = append(pos, arg)
		}
	}
	return append(flags, pos...)
}

func runSelftest(args []string) {
	fs := flag.NewFlagSet("selftest", flag.ExitOnError)
	platformRoot := fs.String("platform-root", "", "Racine du dépôt Compliance Platform")
	_ = fs.Parse(args)

	if *platformRoot == "" {
		*platformRoot = findPlatformRoot()
	}

	passed, steps := selftest.Run(*platformRoot)
	selftest.PrintResults(passed, steps)

	if !passed {
		os.Exit(1)
	}
	os.Exit(0)
}
