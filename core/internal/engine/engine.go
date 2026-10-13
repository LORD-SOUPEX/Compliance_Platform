package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"compliance/internal/catalog"
	"compliance/internal/discovery"
	"compliance/internal/matrix"
	"compliance/internal/report"
)

// ComplianceOptions configures the full compliance run.
type ComplianceOptions struct {
	RepoRoot                string
	PlatformRoot            string
	CatalogPath             string
	TimeoutSeconds          int
	GlobalTimeoutSeconds    int
	MaxOutputBytesPerStream int64
	MaximumControls         int
	AllowNetwork            bool
	AllowCodeExecution      bool
	PlanOnly                bool
	RedactionPatterns       []string
	RedactionReplacement   string
	PlatformQualification   string
	RunID                   string
	CandidateResolver       matrix.CandidateToolResolver
	OnControlStart          func(ctrl *PlannedControl)
	OnControlDone           func(ctrl *PlannedControl, res *report.ExecutionResult)
}

// RunCompliance executes the entire Phase 3 compliance workflow:
// Discovery -> Capability Matrix -> Tool Resolution -> Execution Plan -> Control Execution -> Canonical Report.
func RunCompliance(ctx context.Context, opts ComplianceOptions) (*report.Report, error) {
	totalStart := time.Now()

	repoRoot := opts.RepoRoot
	if repoRoot == "" {
		repoRoot = "."
	}
	absRepo, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("chemin de dépôt invalide: %w", err)
	}

	platformRoot := opts.PlatformRoot
	if platformRoot == "" {
		platformRoot = absRepo
	}

	catalogPath := opts.CatalogPath
	if catalogPath == "" {
		catalogPath = filepath.Join(platformRoot, ".config", "control-catalog.json")
	}

	// 1. Load catalog
	cat, err := catalog.LoadCatalog(catalogPath)
	if err != nil {
		return nil, fmt.Errorf("chargement du catalogue de contrôle impossible: %w", err)
	}

	// 2. Discovery
	discStart := time.Now()
	discResult, err := discovery.DiscoverAll(absRepo)
	if err != nil {
		return nil, fmt.Errorf("découverte des technologies échouée: %w", err)
	}
	discMs := time.Since(discStart).Milliseconds()

	// 3. Capability Matrix & Tool Resolution
	resolverStart := time.Now()
	plat := matrix.DetectPlatform()
	candidateResolver := opts.CandidateResolver
	if candidateResolver == nil {
		candidateResolver = &matrix.DefaultCandidateResolver{PlatformRoot: platformRoot}
	}

	matrixEntries := matrix.BuildCapabilityMatrix(discResult.Technologies, cat, plat, candidateResolver, absRepo)
	resolutionEntries := matrix.ResolveCapabilityTools(matrixEntries)
	resolverMs := time.Since(resolverStart).Milliseconds()

	matrix.PopulateDiscovery(discResult, cat, plat, candidateResolver, absRepo)

	// 4. Execution Plan
	planOpts := PlanOptions{
		TimeoutSeconds:          opts.TimeoutSeconds,
		GlobalTimeoutSeconds:    opts.GlobalTimeoutSeconds,
		MaxOutputBytesPerStream: opts.MaxOutputBytesPerStream,
		MaximumControls:         opts.MaximumControls,
		AllowNetwork:            opts.AllowNetwork,
		AllowCodeExecution:      opts.AllowCodeExecution,
	}

	execPlan, plannedControls, err := BuildCompliancePlan(discResult.Technologies, matrixEntries, resolutionEntries, absRepo, planOpts)
	if err != nil {
		return nil, fmt.Errorf("construction du plan de conformité échouée: %w", err)
	}

	// 5. Redactor
	redactor, err := NewRedactor(opts.RedactionPatterns, opts.RedactionReplacement)
	if err != nil {
		return nil, fmt.Errorf("initialisation du masquage regex échouée: %w", err)
	}

	// 6. Execution
	var results []report.ExecutionResult
	complianceStart := time.Now()

	if !opts.PlanOnly && discResult.ScanComplete {
		results, err = ExecuteCompliancePlan(ctx, execPlan, plannedControls, ExecutionOptions{
			PlatformRoot:   platformRoot,
			GlobalTimeout:  time.Duration(execPlan.Budgets.TimeoutSeconds) * time.Second,
			Redactor:       redactor,
			OnControlStart: opts.OnControlStart,
			OnControlDone:  opts.OnControlDone,
		})
		if err != nil {
			return nil, fmt.Errorf("exécution du plan de conformité échouée: %w", err)
		}
	}
	complianceMs := time.Since(complianceStart).Milliseconds()
	if opts.PlanOnly {
		complianceMs = 0
	}

	// 7. Build Canonical Report
	totalMs := time.Since(totalStart).Milliseconds()
	reportingMs := totalMs - discMs - resolverMs - complianceMs
	if reportingMs < 0 {
		reportingMs = 0
	}

	stageMetrics := &report.Metrics{
		DiscoveryMs:  discMs,
		ResolverMs:   resolverMs,
		ComplianceMs: complianceMs,
		ReportingMs:  reportingMs,
	}

	var catSha *string
	if cat.ContentSHA256 != "" {
		s := cat.ContentSHA256
		catSha = &s
	}

	rep := report.BuildComplianceReport(report.ReportOptions{
		Repository:                  absRepo,
		RunID:                       opts.RunID,
		Platform:                    plat.ID,
		DiscoveryData:               discResult,
		MatrixData:                  discResult.CapabilityMatrix,
		ResolverData:                discResult.ToolResolution,
		Plan:                        *execPlan,
		Results:                     results,
		Metrics:                     stageMetrics,
		CatalogSHA256:               catSha,
		PlatformQualificationStatus: opts.PlatformQualification,
		RedactionApplied:            redactor != nil && len(redactor.Patterns) > 0,
		PlanOnly:                    opts.PlanOnly,
		ScanComplete:                discResult.ScanComplete,
	})

	return rep, nil
}
