package awslambda

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/alphabravocompany/constellation/internal/scanner"
)

func TestCollectReportsLambdaPackageEvidenceWithLayers(t *testing.T) {
	functionZip := testZip(t, map[string]string{
		"handler.py": "print('ok')\n",
	})
	layerZip := testZip(t, map[string]string{
		"python/requirements.txt": "django==4.2.0\n",
	})
	layerARN := "arn:aws:lambda:us-east-1:123456789012:layer:deps:7"
	fn := lambdatypes.FunctionConfiguration{
		FunctionArn:   awssdk.String("arn:aws:lambda:us-east-1:123456789012:function:payments"),
		FunctionName:  awssdk.String("payments"),
		Runtime:       lambdatypes.RuntimePython311,
		Version:       awssdk.String("$LATEST"),
		Architectures: []lambdatypes.Architecture{lambdatypes.ArchitectureX8664},
		CodeSha256:    awssdk.String("code-sha"),
		Role:          awssdk.String("arn:aws:iam::123456789012:role/payments"),
		Handler:       awssdk.String("handler.main"),
		PackageType:   lambdatypes.PackageTypeZip,
		Layers:        []lambdatypes.Layer{{Arn: awssdk.String(layerARN)}},
	}
	client := &fakeLambdaAPI{
		listPages: []*lambda.ListFunctionsOutput{{
			Functions: []lambdatypes.FunctionConfiguration{fn},
		}},
		getFunction: &lambda.GetFunctionOutput{
			Configuration: &fn,
			Code:          &lambdatypes.FunctionCodeLocation{Location: awssdk.String("function.zip")},
		},
		layer: &lambda.GetLayerVersionByArnOutput{
			Content: &lambdatypes.LayerVersionContentOutput{Location: awssdk.String("layer.zip")},
		},
	}
	downloader := fakeDownloader{objects: map[string][]byte{
		"function.zip": functionZip,
		"layer.zip":    layerZip,
	}}
	cataloger := fakeCataloger{t: t}
	reporter := &fakeReporter{}

	summary, err := Collect(context.Background(), client, downloader, cataloger, reporter, Options{
		Region:              "us-east-1",
		IncludeLayers:       true,
		IncludeRoleAnalysis: true,
		RoleAnalyzer:        fakeRoleAnalyzer{},
		TempDir:             t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Discovered != 1 || summary.Reported != 1 || summary.PackageCount != 1 || summary.Failed != 0 {
		t.Fatalf("summary = %+v", summary)
	}
	if client.layerCalls != 1 {
		t.Fatalf("layer calls = %d", client.layerCalls)
	}
	if len(reporter.payloads) != 1 {
		t.Fatalf("reports = %d", len(reporter.payloads))
	}
	got := reporter.payloads[0]
	if got.FunctionRef != "arn:aws:lambda:us-east-1:123456789012:function:payments" ||
		got.FunctionName != "payments" ||
		got.Provider != "aws" ||
		got.AccountID != "123456789012" ||
		got.Region != "us-east-1" ||
		got.Runtime != "python3.11" ||
		got.Architecture != "x86_64" ||
		got.CodeSHA256 != "code-sha" ||
		got.Role == "" ||
		got.Handler != "handler.main" ||
		got.PackageType != "Zip" ||
		len(got.Layers) != 1 ||
		got.Layers[0] != layerARN ||
		got.PermissionAnalysis == nil ||
		got.PermissionAnalysis.Level != "high" {
		t.Fatalf("payload = %+v", got)
	}
	if got.Packages[0].Name != "django" || got.Packages[0].Ecosystem != "pypi" || got.Packages[0].BaseImage != got.FunctionRef {
		t.Fatalf("package = %+v", got.Packages[0])
	}
}

func TestCollectRejectsUnsafeLambdaZipPath(t *testing.T) {
	badZip := testZip(t, map[string]string{
		"../escape": "bad",
	})
	fn := lambdatypes.FunctionConfiguration{
		FunctionArn:  awssdk.String("arn:aws:lambda:us-east-1:123456789012:function:bad"),
		FunctionName: awssdk.String("bad"),
		PackageType:  lambdatypes.PackageTypeZip,
	}
	client := &fakeLambdaAPI{
		listPages: []*lambda.ListFunctionsOutput{{Functions: []lambdatypes.FunctionConfiguration{fn}}},
		getFunction: &lambda.GetFunctionOutput{
			Configuration: &fn,
			Code:          &lambdatypes.FunctionCodeLocation{Location: awssdk.String("bad.zip")},
		},
	}
	_, err := Collect(context.Background(), client, fakeDownloader{objects: map[string][]byte{"bad.zip": badZip}}, fakeCataloger{t: t}, &fakeReporter{}, Options{TempDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "unsafe zip path") {
		t.Fatalf("error = %v", err)
	}
}

func TestCollectSkipsImagePackageType(t *testing.T) {
	fn := lambdatypes.FunctionConfiguration{
		FunctionArn:  awssdk.String("arn:aws:lambda:us-east-1:123456789012:function:image-fn"),
		FunctionName: awssdk.String("image-fn"),
		PackageType:  lambdatypes.PackageTypeImage,
	}
	client := &fakeLambdaAPI{
		listPages:   []*lambda.ListFunctionsOutput{{Functions: []lambdatypes.FunctionConfiguration{fn}}},
		getFunction: &lambda.GetFunctionOutput{Configuration: &fn},
	}
	summary, err := Collect(context.Background(), client, fakeDownloader{}, fakeCataloger{t: t}, &fakeReporter{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Discovered != 1 || summary.Skipped != 1 || summary.Reported != 0 {
		t.Fatalf("summary = %+v", summary)
	}
}

type fakeLambdaAPI struct {
	listPages   []*lambda.ListFunctionsOutput
	listCalls   int
	getFunction *lambda.GetFunctionOutput
	layer       *lambda.GetLayerVersionByArnOutput
	layerCalls  int
}

func (f *fakeLambdaAPI) ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if f.listCalls >= len(f.listPages) {
		return &lambda.ListFunctionsOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeLambdaAPI) GetFunction(context.Context, *lambda.GetFunctionInput, ...func(*lambda.Options)) (*lambda.GetFunctionOutput, error) {
	return f.getFunction, nil
}

func (f *fakeLambdaAPI) GetLayerVersionByArn(context.Context, *lambda.GetLayerVersionByArnInput, ...func(*lambda.Options)) (*lambda.GetLayerVersionByArnOutput, error) {
	f.layerCalls++
	return f.layer, nil
}

type fakeDownloader struct {
	objects map[string][]byte
}

func (f fakeDownloader) Download(_ context.Context, url string, dst string, _ int64) (int64, error) {
	body := f.objects[url]
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return 0, err
	}
	if err := os.WriteFile(dst, body, 0o600); err != nil {
		return 0, err
	}
	return int64(len(body)), nil
}

type fakeCataloger struct {
	t *testing.T
}

func (f fakeCataloger) Catalog(_ context.Context, path string, runtime string, sourceRef string) ([]scanner.Package, error) {
	f.t.Helper()
	if _, err := os.Stat(filepath.Join(path, "handler.py")); err != nil {
		f.t.Fatalf("function zip was not extracted under %s: %v", path, err)
	}
	var sawLayer bool
	if err := filepath.WalkDir(path, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if filepath.Base(path) == "requirements.txt" {
			sawLayer = true
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if strings.Contains(sourceRef, "payments") && !sawLayer {
		f.t.Fatal("layer zip was not extracted")
	}
	return []scanner.Package{{
		Ecosystem: "pypi",
		Name:      "django",
		Version:   "4.2.0",
		BaseImage: sourceRef,
		Locations: []scanner.PackageLocation{{
			Path: "/python/requirements.txt",
		}},
	}}, nil
}

type fakeReporter struct {
	payloads []PackageReport
}

func (f *fakeReporter) Report(_ context.Context, payload PackageReport) (ReportResponse, error) {
	f.payloads = append(f.payloads, payload)
	return ReportResponse{OK: true, PackageCount: len(payload.Packages)}, nil
}

type fakeRoleAnalyzer struct{}

func (fakeRoleAnalyzer) AnalyzeRole(_ context.Context, roleARN string) (RolePermissionAnalysis, error) {
	return RolePermissionAnalysis{
		Status:   "complete",
		Level:    "high",
		RoleARN:  roleARN,
		RoleName: roleNameFromARN(roleARN),
		Findings: []RolePermissionFinding{{
			ID:       "test-role-risk",
			Severity: "high",
			Title:    "role risk",
		}},
	}, nil
}

func testZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
