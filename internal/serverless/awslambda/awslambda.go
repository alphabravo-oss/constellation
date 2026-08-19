package awslambda

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/alphabravocompany/constellation/internal/scanner"
)

const (
	defaultMaxZipBytes       int64 = 512 << 20
	defaultMaxExtractedBytes int64 = 1 << 30
)

// LambdaAPI is the subset of the AWS Lambda API used by the collector.
type LambdaAPI interface {
	ListFunctions(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	GetFunction(ctx context.Context, params *lambda.GetFunctionInput, optFns ...func(*lambda.Options)) (*lambda.GetFunctionOutput, error)
	GetLayerVersionByArn(ctx context.Context, params *lambda.GetLayerVersionByArnInput, optFns ...func(*lambda.Options)) (*lambda.GetLayerVersionByArnOutput, error)
}

type Cataloger interface {
	Catalog(ctx context.Context, path string, runtime string, sourceRef string) ([]scanner.Package, error)
}

type Reporter interface {
	Report(ctx context.Context, payload PackageReport) (ReportResponse, error)
}

type Downloader interface {
	Download(ctx context.Context, url string, dst string, maxBytes int64) (int64, error)
}

type Options struct {
	Region              string
	AccountID           string
	FunctionName        string
	Qualifier           string
	IncludeVersions     bool
	IncludeLayers       bool
	IncludeRoleAnalysis bool
	RoleAnalyzer        RoleAnalyzer
	Limit               int
	SourceType          string
	SourceRef           string
	PackageSource       string
	TempDir             string
	MaxZipBytes         int64
	MaxExtractedBytes   int64
}

type PackageReport struct {
	FunctionRef        string                  `json:"function_ref"`
	FunctionName       string                  `json:"function_name,omitempty"`
	Provider           string                  `json:"provider,omitempty"`
	AccountID          string                  `json:"account_id,omitempty"`
	Region             string                  `json:"region,omitempty"`
	Runtime            string                  `json:"runtime,omitempty"`
	Version            string                  `json:"version,omitempty"`
	Architecture       string                  `json:"architecture,omitempty"`
	SourceType         string                  `json:"source_type,omitempty"`
	SourceRef          string                  `json:"source_ref,omitempty"`
	ObservedAt         time.Time               `json:"observed_at,omitempty"`
	Packages           []scanner.Package       `json:"packages,omitempty"`
	PackageSource      string                  `json:"package_source,omitempty"`
	CodeSHA256         string                  `json:"code_sha256,omitempty"`
	Role               string                  `json:"role,omitempty"`
	Handler            string                  `json:"handler,omitempty"`
	PackageType        string                  `json:"package_type,omitempty"`
	Layers             []string                `json:"layers,omitempty"`
	PermissionAnalysis *RolePermissionAnalysis `json:"permission_analysis,omitempty"`
}

type ReportResponse struct {
	OK              bool   `json:"ok"`
	ScanTargetID    string `json:"scan_target_id,omitempty"`
	ScanEvidenceID  string `json:"scan_evidence_id,omitempty"`
	InventoryHash   string `json:"inventory_hash,omitempty"`
	PackageCount    int    `json:"package_count,omitempty"`
	ScanJobEnqueued bool   `json:"scan_job_enqueued,omitempty"`
	ScanJobID       string `json:"scan_job_id,omitempty"`
}

type Summary struct {
	Discovered    int
	Reported      int
	Skipped       int
	Failed        int
	PackageCount  int
	FunctionNames []string
	Errors        []string
}

type SyftCataloger struct {
	Binary  string
	Timeout time.Duration
}

func (c SyftCataloger) Catalog(ctx context.Context, path string, runtime string, sourceRef string) ([]scanner.Package, error) {
	res, err := (&scanner.SyftEngine{Binary: c.Binary}).Scan(ctx, path, scanner.ScanOptions{
		SBOMOnly: true,
		Timeout:  c.Timeout,
	})
	if err != nil {
		return nil, err
	}
	packages := append([]scanner.Package(nil), res.Packages...)
	defaultEcosystem := ecosystemFromRuntime(runtime)
	for i := range packages {
		if packages[i].BaseImage == "" || packages[i].BaseImage == path {
			packages[i].BaseImage = sourceRef
		}
		if packages[i].Ecosystem == "" && defaultEcosystem != "" {
			packages[i].Ecosystem = defaultEcosystem
		}
	}
	return packages, nil
}

type HTTPDownloader struct {
	Client *http.Client
}

func (d HTTPDownloader) Download(ctx context.Context, url string, dst string, maxBytes int64) (int64, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxZipBytes
	}
	client := d.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("download lambda package: %s", resp.Status)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return 0, err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	limited := &io.LimitedReader{R: resp.Body, N: maxBytes + 1}
	n, err := io.Copy(out, limited)
	if err != nil {
		return n, err
	}
	if n > maxBytes {
		return n, fmt.Errorf("lambda package exceeds max zip size %d bytes", maxBytes)
	}
	return n, nil
}

func Collect(ctx context.Context, client LambdaAPI, downloader Downloader, cataloger Cataloger, reporter Reporter, opts Options) (Summary, error) {
	if client == nil {
		return Summary{}, errors.New("lambda client required")
	}
	if downloader == nil {
		downloader = HTTPDownloader{}
	}
	if cataloger == nil {
		return Summary{}, errors.New("cataloger required")
	}
	if reporter == nil {
		return Summary{}, errors.New("reporter required")
	}
	opts = opts.withDefaults()
	summary := Summary{}
	var errs []error

	if strings.TrimSpace(opts.FunctionName) != "" {
		summary.Discovered = 1
		if err := processFunction(ctx, client, downloader, cataloger, reporter, opts, lambdatypes.FunctionConfiguration{
			FunctionName: awssdk.String(strings.TrimSpace(opts.FunctionName)),
		}, &summary); err != nil {
			errs = append(errs, err)
			summary.Errors = append(summary.Errors, err.Error())
		}
		return summary, errors.Join(errs...)
	}

	var marker *string
	for {
		input := &lambda.ListFunctionsInput{
			Marker:   marker,
			MaxItems: awssdk.Int32(pageSizeForLimit(opts.Limit, summary.Discovered)),
		}
		if opts.IncludeVersions {
			input.FunctionVersion = lambdatypes.FunctionVersionAll
		}
		out, err := client.ListFunctions(ctx, input)
		if err != nil {
			return summary, err
		}
		for _, fn := range out.Functions {
			if opts.Limit > 0 && summary.Discovered >= opts.Limit {
				return summary, errors.Join(errs...)
			}
			summary.Discovered++
			if err := processFunction(ctx, client, downloader, cataloger, reporter, opts, fn, &summary); err != nil {
				errs = append(errs, err)
				summary.Errors = append(summary.Errors, err.Error())
			}
		}
		if opts.Limit > 0 && summary.Discovered >= opts.Limit {
			break
		}
		if out.NextMarker == nil || strings.TrimSpace(*out.NextMarker) == "" {
			break
		}
		marker = out.NextMarker
	}
	return summary, errors.Join(errs...)
}

func (o Options) withDefaults() Options {
	o.Region = strings.TrimSpace(o.Region)
	o.AccountID = strings.TrimSpace(o.AccountID)
	o.FunctionName = strings.TrimSpace(o.FunctionName)
	o.Qualifier = strings.TrimSpace(o.Qualifier)
	o.SourceType = strings.TrimSpace(o.SourceType)
	if o.SourceType == "" {
		o.SourceType = "discoverer"
	}
	o.SourceRef = strings.TrimSpace(o.SourceRef)
	o.PackageSource = strings.TrimSpace(o.PackageSource)
	if o.PackageSource == "" {
		o.PackageSource = "syft"
	}
	if o.MaxZipBytes <= 0 {
		o.MaxZipBytes = defaultMaxZipBytes
	}
	if o.MaxExtractedBytes <= 0 {
		o.MaxExtractedBytes = defaultMaxExtractedBytes
	}
	return o
}

func pageSizeForLimit(limit, seen int) int32 {
	if limit <= 0 {
		return 50
	}
	remaining := limit - seen
	if remaining <= 0 {
		return 1
	}
	if remaining > 50 {
		return 50
	}
	return int32(remaining)
}

func processFunction(ctx context.Context, client LambdaAPI, downloader Downloader, cataloger Cataloger, reporter Reporter, opts Options, listed lambdatypes.FunctionConfiguration, summary *Summary) error {
	lookup := functionLookupName(listed)
	if lookup == "" {
		summary.Skipped++
		return nil
	}
	getInput := &lambda.GetFunctionInput{FunctionName: awssdk.String(lookup)}
	if opts.Qualifier != "" {
		getInput.Qualifier = awssdk.String(opts.Qualifier)
	}
	fn, err := client.GetFunction(ctx, getInput)
	if err != nil {
		summary.Failed++
		return fmt.Errorf("%s: get function: %w", lookup, err)
	}
	cfg := listed
	if fn.Configuration != nil {
		cfg = *fn.Configuration
	}
	name := awssdk.ToString(cfg.FunctionName)
	ref := functionRef(cfg)
	if ref == "" {
		ref = lookup
	}
	summary.FunctionNames = append(summary.FunctionNames, firstNonEmpty(name, ref))

	if cfg.PackageType != "" && cfg.PackageType != lambdatypes.PackageTypeZip {
		summary.Skipped++
		return nil
	}
	if fn.Code == nil || strings.TrimSpace(awssdk.ToString(fn.Code.Location)) == "" {
		summary.Failed++
		return fmt.Errorf("%s: missing deployment package download URL", ref)
	}

	workDir, err := os.MkdirTemp(opts.TempDir, "constellation-lambda-*")
	if err != nil {
		summary.Failed++
		return fmt.Errorf("%s: temp dir: %w", ref, err)
	}
	defer os.RemoveAll(workDir)

	zipPath := filepath.Join(workDir, "function.zip")
	extractDir := filepath.Join(workDir, "package")
	if err := downloadAndExtract(ctx, downloader, awssdk.ToString(fn.Code.Location), zipPath, extractDir, opts); err != nil {
		summary.Failed++
		return fmt.Errorf("%s: function package: %w", ref, err)
	}
	if opts.IncludeLayers {
		if err := extractFunctionLayers(ctx, client, downloader, cfg, filepath.Join(workDir, "layers"), filepath.Join(extractDir, "layers"), opts); err != nil {
			summary.Failed++
			return fmt.Errorf("%s: layer package: %w", ref, err)
		}
	}

	runtime := string(cfg.Runtime)
	packages, err := cataloger.Catalog(ctx, extractDir, runtime, ref)
	if err != nil {
		summary.Failed++
		return fmt.Errorf("%s: catalog package: %w", ref, err)
	}
	if len(packages) == 0 {
		summary.Skipped++
		return nil
	}
	payload := packageReportFromFunction(cfg, opts, packages, analyzeFunctionRole(ctx, opts, cfg))
	if _, err := reporter.Report(ctx, payload); err != nil {
		summary.Failed++
		return fmt.Errorf("%s: report package evidence: %w", ref, err)
	}
	summary.Reported++
	summary.PackageCount += len(packages)
	return nil
}

func downloadAndExtract(ctx context.Context, downloader Downloader, url string, zipPath string, extractDir string, opts Options) error {
	if _, err := downloader.Download(ctx, url, zipPath, opts.MaxZipBytes); err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if err := extractZip(zipPath, extractDir, opts.MaxExtractedBytes); err != nil {
		return fmt.Errorf("extract: %w", err)
	}
	return nil
}

func extractFunctionLayers(ctx context.Context, client LambdaAPI, downloader Downloader, cfg lambdatypes.FunctionConfiguration, zipRoot string, extractRoot string, opts Options) error {
	for i, arn := range layerARNs(cfg.Layers) {
		out, err := client.GetLayerVersionByArn(ctx, &lambda.GetLayerVersionByArnInput{Arn: awssdk.String(arn)})
		if err != nil {
			return fmt.Errorf("%s: get layer: %w", arn, err)
		}
		if out == nil || out.Content == nil || strings.TrimSpace(awssdk.ToString(out.Content.Location)) == "" {
			return fmt.Errorf("%s: missing layer download URL", arn)
		}
		layerName := fmt.Sprintf("%02d-%s", i+1, safeLayerDirName(arn))
		if err := downloadAndExtract(
			ctx,
			downloader,
			awssdk.ToString(out.Content.Location),
			filepath.Join(zipRoot, layerName+".zip"),
			filepath.Join(extractRoot, layerName),
			opts,
		); err != nil {
			return fmt.Errorf("%s: %w", arn, err)
		}
	}
	return nil
}

func analyzeFunctionRole(ctx context.Context, opts Options, cfg lambdatypes.FunctionConfiguration) *RolePermissionAnalysis {
	roleARN := strings.TrimSpace(awssdk.ToString(cfg.Role))
	if !opts.IncludeRoleAnalysis || roleARN == "" {
		return nil
	}
	if opts.RoleAnalyzer == nil {
		return &RolePermissionAnalysis{
			Status:   "unavailable",
			Level:    "unknown",
			RoleARN:  roleARN,
			RoleName: roleNameFromARN(roleARN),
			Error:    "role analyzer not configured",
		}
	}
	analysis, err := opts.RoleAnalyzer.AnalyzeRole(ctx, roleARN)
	if err != nil {
		return &RolePermissionAnalysis{
			Status:   "unavailable",
			Level:    "unknown",
			RoleARN:  roleARN,
			RoleName: roleNameFromARN(roleARN),
			Error:    err.Error(),
		}
	}
	if analysis.Status == "" {
		analysis.Status = "complete"
	}
	if analysis.Level == "" {
		analysis.Level = permissionLevel(analysis.Findings)
	}
	return &analysis
}

func packageReportFromFunction(cfg lambdatypes.FunctionConfiguration, opts Options, packages []scanner.Package, permissionAnalysis *RolePermissionAnalysis) PackageReport {
	ref := functionRef(cfg)
	name := awssdk.ToString(cfg.FunctionName)
	accountID, region := accountRegionFromLambdaARN(ref)
	if opts.AccountID != "" {
		accountID = opts.AccountID
	}
	if opts.Region != "" {
		region = opts.Region
	}
	return PackageReport{
		FunctionRef:        firstNonEmpty(ref, name),
		FunctionName:       name,
		Provider:           "aws",
		AccountID:          accountID,
		Region:             region,
		Runtime:            string(cfg.Runtime),
		Version:            awssdk.ToString(cfg.Version),
		Architecture:       firstArchitecture(cfg.Architectures),
		SourceType:         opts.SourceType,
		SourceRef:          sourceRef(opts, accountID, region, firstNonEmpty(ref, name)),
		ObservedAt:         time.Now().UTC(),
		Packages:           packages,
		PackageSource:      opts.PackageSource,
		CodeSHA256:         awssdk.ToString(cfg.CodeSha256),
		Role:               awssdk.ToString(cfg.Role),
		Handler:            awssdk.ToString(cfg.Handler),
		PackageType:        string(cfg.PackageType),
		Layers:             layerARNs(cfg.Layers),
		PermissionAnalysis: permissionAnalysis,
	}
}

func extractZip(zipPath string, dst string, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = defaultMaxExtractedBytes
	}
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	var total int64
	for _, file := range reader.File {
		target, err := safeZipTarget(dst, file.Name)
		if err != nil {
			return err
		}
		if target == "" {
			continue
		}
		mode := file.Mode()
		if mode.IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if mode&os.ModeSymlink != 0 {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		rc, err := file.Open()
		if err != nil {
			return err
		}
		if total >= maxBytes {
			_ = rc.Close()
			return fmt.Errorf("extracted lambda package exceeds max size %d bytes", maxBytes)
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fileMode(mode))
		if err != nil {
			_ = rc.Close()
			return err
		}
		remaining := maxBytes - total
		limited := &io.LimitedReader{R: rc, N: remaining + 1}
		n, copyErr := io.Copy(out, limited)
		closeErr := out.Close()
		readCloseErr := rc.Close()
		total += n
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if readCloseErr != nil {
			return readCloseErr
		}
		if total > maxBytes {
			return fmt.Errorf("extracted lambda package exceeds max size %d bytes", maxBytes)
		}
	}
	return nil
}

func safeZipTarget(root string, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." {
		return "", nil
	}
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("unsafe zip path %q", name)
	}
	target := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("unsafe zip path %q", name)
	}
	return target, nil
}

func fileMode(mode os.FileMode) os.FileMode {
	perm := mode.Perm()
	if perm == 0 {
		perm = 0o600
	}
	return 0o600 | (perm & 0o100)
}

func functionLookupName(fn lambdatypes.FunctionConfiguration) string {
	if ref := awssdk.ToString(fn.FunctionArn); strings.TrimSpace(ref) != "" {
		return strings.TrimSpace(ref)
	}
	return strings.TrimSpace(awssdk.ToString(fn.FunctionName))
}

func functionRef(fn lambdatypes.FunctionConfiguration) string {
	if ref := awssdk.ToString(fn.FunctionArn); strings.TrimSpace(ref) != "" {
		return strings.TrimSpace(ref)
	}
	return strings.TrimSpace(awssdk.ToString(fn.FunctionName))
}

func accountRegionFromLambdaARN(arn string) (string, string) {
	parts := strings.Split(arn, ":")
	if len(parts) < 7 || parts[0] != "arn" || parts[2] != "lambda" {
		return "", ""
	}
	return parts[4], parts[3]
}

func firstArchitecture(values []lambdatypes.Architecture) string {
	if len(values) == 0 {
		return ""
	}
	return string(values[0])
}

func layerARNs(layers []lambdatypes.Layer) []string {
	out := make([]string, 0, len(layers))
	seen := map[string]struct{}{}
	for _, layer := range layers {
		if arn := strings.TrimSpace(awssdk.ToString(layer.Arn)); arn != "" {
			if _, ok := seen[arn]; ok {
				continue
			}
			seen[arn] = struct{}{}
			out = append(out, arn)
		}
	}
	return out
}

func safeLayerDirName(arn string) string {
	arn = strings.TrimSpace(arn)
	if arn == "" {
		return "layer"
	}
	replacer := strings.NewReplacer(":", "_", "/", "_", "\\", "_", " ", "_")
	name := replacer.Replace(arn)
	if len(name) > 120 {
		name = name[len(name)-120:]
	}
	return name
}

func sourceRef(opts Options, accountID, region, ref string) string {
	if opts.SourceRef != "" {
		return opts.SourceRef
	}
	parts := []string{"aws"}
	if accountID != "" {
		parts = append(parts, accountID)
	}
	if region != "" {
		parts = append(parts, region)
	}
	if ref != "" {
		parts = append(parts, ref)
	}
	return strings.Join(parts, "/")
}

func ecosystemFromRuntime(runtime string) string {
	runtime = strings.ToLower(strings.TrimSpace(runtime))
	switch {
	case strings.HasPrefix(runtime, "python"):
		return "pypi"
	case strings.HasPrefix(runtime, "nodejs"):
		return "npm"
	case strings.HasPrefix(runtime, "java"):
		return "maven"
	case strings.HasPrefix(runtime, "dotnet"):
		return "nuget"
	case strings.HasPrefix(runtime, "ruby"):
		return "gem"
	case strings.HasPrefix(runtime, "go"):
		return "go"
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
