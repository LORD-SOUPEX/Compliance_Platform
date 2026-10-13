package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"compliance/internal/discovery"
	"compliance/internal/distribution"
	"compliance/internal/engine"
)

const version = "0.1.0-phase0-go"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	command := os.Args[1]
	switch command {
	case "discovery":
		runDiscovery(os.Args[2:])
	case "runtime":
		if len(os.Args) < 3 || os.Args[2] != "sync" {
			fmt.Fprintln(os.Stderr, "Usage: compliance runtime sync [options]")
			os.Exit(2)
		}
		runRuntimeSync(os.Args[3:])
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
	fmt.Fprintf(os.Stderr, `Compliance Platform - Cœur Multi-OS (Phase 0)

Usage:
  compliance <commande> [arguments]

Sous-commandes disponibles:
  discovery <chemin>      Découvre les sources et racines Python d'un répertoire
  runtime sync [options]  Télécharge et vérifie les outils depuis un manifeste statique signé
  run <chemin> [options]  Exécute le pipeline Python (Ruff + Bandit) et produit le rapport v1

Options globales:
  version                 Affiche la version du binaire
`)
}

func runDiscovery(args []string) {
	fs := flag.NewFlagSet("discovery", flag.ExitOnError)
	indent := fs.Bool("indent", true, "Formater la sortie JSON")
	_ = fs.Parse(args)

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	res, err := discovery.DiscoverAll(target)
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

func runRuntimeSync(args []string) {
	fs := flag.NewFlagSet("runtime sync", flag.ExitOnError)
	manifestPath := fs.String("manifest", ".config/runtime-manifest.json", "Chemin ou URL du manifeste")
	sigPath := fs.String("sig", ".config/runtime-manifest.json.sig", "Chemin ou URL de la signature Ed25519")
	cacheDir := fs.String("cache-dir", defaultCacheDir(), "Dossier local de cache des outils")
	pubKeyHex := fs.String("pubkey", distribution.DefaultPhase0PublicKeyHex, "Clé publique Ed25519 (hex)")
	caBundle := fs.String("ca-bundle", "", "Chemin vers le bundle CA d'entreprise")
	platform := fs.String("platform", distribution.DetectPlatform(), "Plateforme cible")
	_ = fs.Parse(args)

	pubBytes, err := hex.DecodeString(*pubKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		fmt.Fprintf(os.Stderr, "[ERROR] Clé publique Ed25519 invalide\n")
		os.Exit(2)
	}

	fmt.Printf("[INFO] Synchronisation runtime pour la plateforme %s...\n", *platform)
	res, err := distribution.SyncRuntime(distribution.SyncOptions{
		ManifestPath: *manifestPath,
		SigPath:      *sigPath,
		CacheDir:     *cacheDir,
		Platform:     *platform,
		PublicKey:    ed25519.PublicKey(pubBytes),
		CABundlePath: *caBundle,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Échec de synchronisation: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[PASS] Synchronisation réussie pour %s:\n", res.Platform)
	for name, path := range res.SyncedTools {
		fmt.Printf("  - %s -> %s\n", name, path)
	}
	os.Exit(0)
}

func runPipeline(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	outputPath := fs.String("output", "", "Chemin où écrire le rapport JSON (défaut: stdout)")
	ruffPath := fs.String("ruff", "", "Chemin vers l'exécutable ruff (auto-détecté si omis)")
	banditPath := fs.String("bandit", "", "Chemin vers l'exécutable bandit (auto-détecté si omis)")
	caBundle := fs.String("ca-bundle", defaultCABundle(), "Bundle de certificats d'entreprise pour les outils Python")
	timeoutSec := fs.Int("timeout", 300, "Délai maximum par contrôle en secondes")
	_ = fs.Parse(reorderFlags(args))

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	absTarget, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Chemin invalide: %v\n", err)
		os.Exit(2)
	}

	resolvedRuff := resolveTool("ruff", *ruffPath)
	resolvedBandit := resolveTool("bandit", *banditPath)

	if resolvedRuff.Executable == "" {
		fmt.Fprintf(os.Stderr, "[ERROR] Outil introuvable : ruff (exécutez 'compliance runtime sync' ou fournissez --ruff)\n")
		os.Exit(2)
	}
	if resolvedBandit.Executable == "" {
		fmt.Fprintf(os.Stderr, "[ERROR] Outil introuvable : bandit (fournissez --bandit)\n")
		os.Exit(2)
	}

	opts := engine.PipelineOptions{
		RepoRoot:     absTarget,
		RuffPath:     resolvedRuff.Executable,
		BanditPath:   resolvedBandit.Executable,
		BanditArgs:   resolvedBandit.Args,
		BanditEnv:    resolvedBandit.Env,
		CABundlePath: *caBundle,
		Timeout:      time.Duration(*timeoutSec) * time.Second,
		ProgressHandler: func(controlID, status string) {
			fmt.Fprintf(os.Stderr, "  [%-8s] %s\n", strings.ToUpper(status), controlID)
		},
	}

	fmt.Fprintf(os.Stderr, "[INFO] Lancement du pipeline Python sur: %s\n", absTarget)
	if *caBundle != "" {
		fmt.Fprintf(os.Stderr, "[INFO] Bundle CA entreprise configuré pour Bandit: %s\n", *caBundle)
	}

	ctx := context.Background()
	rep, err := engine.RunPythonPipeline(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Échec d'exécution du pipeline: %v\n", err)
		os.Exit(2)
	}

	jsonBytes, err := rep.ToJSON(true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Sérialisation du rapport: %v\n", err)
		os.Exit(2)
	}

	if *outputPath != "" {
		if err := os.WriteFile(*outputPath, jsonBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Écriture du rapport sur %s: %v\n", *outputPath, err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "[INFO] Rapport enregistré dans: %s\n", *outputPath)
	} else {
		fmt.Println(string(jsonBytes))
	}

	// Print summary
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

func defaultCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".compliance/tools"
	}
	return filepath.Join(home, ".compliance", "tools")
}

func defaultCABundle() string {
	// Look for windows-root-ca.pem in .tools/cache if present in repo
	candidate := filepath.Join(".tools", "cache", "windows-root-ca.pem")
	if _, err := os.Stat(candidate); err == nil {
		abs, _ := filepath.Abs(candidate)
		return abs
	}
	return ""
}

type ToolInvocation struct {
	Executable string
	Args       []string
	Env        []string
}

func resolveTool(name, override string) ToolInvocation {
	if override != "" {
		if _, err := os.Stat(override); err == nil {
			abs, _ := filepath.Abs(override)
			return ToolInvocation{Executable: abs}
		}
		return ToolInvocation{Executable: override}
	}

	// 1. Check ~/.compliance/tools/bin/<platform>/<name>
	plat := distribution.DetectPlatform()
	cached := filepath.Join(defaultCacheDir(), "bin", plat, name)
	if runtime.GOOS == "windows" {
		cached += ".exe"
	}
	if _, err := os.Stat(cached); err == nil {
		return ToolInvocation{Executable: cached}
	}

	// 2. Check repo .venv/Scripts or .venv/bin
	venvCandidate := filepath.Join(".venv", "Scripts", name+".exe")
	if runtime.GOOS != "windows" {
		venvCandidate = filepath.Join(".venv", "bin", name)
	}
	if _, err := os.Stat(venvCandidate); err == nil {
		abs, _ := filepath.Abs(venvCandidate)
		// On Windows, test if this venv wrapper can actually run without crashing on pyvenv.cfg
		if name == "bandit" {
			testCmd := exec.Command(abs, "--version")
			if testErr := testCmd.Run(); testErr != nil {
				// Broken venv wrapper (relocated drive). Fallback to python -m bandit
				return resolveBanditPythonModule()
			}
		}
		return ToolInvocation{Executable: abs}
	}

	// 3. Special handling for bandit if in .venv/Lib/site-packages
	if name == "bandit" {
		inv := resolveBanditPythonModule()
		if inv.Executable != "" {
			return inv
		}
	}

	// 4. Check system PATH
	if p, err := exec.LookPath(name); err == nil {
		return ToolInvocation{Executable: p}
	}

	return ToolInvocation{}
}

func resolveBanditPythonModule() ToolInvocation {
	pythonCandidates := []string{
		filepath.Join(".tools", "python", "python.exe"),
		"python",
		"python3",
	}

	sitePackages := filepath.Join(".venv", "Lib", "site-packages")
	if runtime.GOOS != "windows" {
		// e.g. .venv/lib/python3.11/site-packages
		matches, _ := filepath.Glob(".venv/lib/python*/site-packages")
		if len(matches) > 0 {
			sitePackages = matches[0]
		}
	}
	absSite, _ := filepath.Abs(sitePackages)

	for _, py := range pythonCandidates {
		if _, err := os.Stat(py); err == nil {
			absPy, _ := filepath.Abs(py)
			return ToolInvocation{
				Executable: absPy,
				Args:       []string{"-m", "bandit", "-q"},
				Env:        []string{"PYTHONPATH=" + absSite},
			}
		}
		if p, err := exec.LookPath(py); err == nil {
			return ToolInvocation{
				Executable: p,
				Args:       []string{"-m", "bandit", "-q"},
				Env:        []string{"PYTHONPATH=" + absSite},
			}
		}
	}
	return ToolInvocation{}
}

func reorderFlags(args []string) []string {
	var flags []string
	var pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flags = append(flags, args[i])
			}
		} else {
			pos = append(pos, arg)
		}
	}
	return append(flags, pos...)
}

