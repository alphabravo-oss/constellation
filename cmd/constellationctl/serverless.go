package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/spf13/cobra"

	"github.com/alphabravocompany/constellation/internal/serverless/awslambda"
)

func serverlessCmd() *cobra.Command {
	var (
		serverFlag string
	)
	c := &cobra.Command{
		Use:   "serverless",
		Short: "Discover and report serverless package evidence",
	}
	c.PersistentFlags().StringVar(&serverFlag, "server", "", "Override Constellation server URL")
	c.AddCommand(serverlessAWSLambdaCmd(&serverFlag))
	return c
}

func serverlessAWSLambdaCmd(serverFlag *string) *cobra.Command {
	c := &cobra.Command{
		Use:   "aws-lambda",
		Short: "Discover AWS Lambda functions and report package evidence",
	}
	c.AddCommand(serverlessAWSLambdaSyncCmd(serverFlag))
	return c
}

func serverlessAWSLambdaSyncCmd(serverFlag *string) *cobra.Command {
	var (
		region                 string
		functionName           string
		qualifier              string
		includeVersions        bool
		includeLayers          bool
		analyzeRolePermissions bool
		limit                  int
		sourceRef              string
		syftBinary             string
		tempDir                string
		timeout                time.Duration
		maxZipMB               int64
		maxExtractedMB         int64
		jsonOut                bool
	)
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Catalog Lambda deployment packages and queue serverless scans",
		Long: `Discovers AWS Lambda functions with the AWS SDK default credential chain,
downloads ZIP deployment packages and layers, catalogs packages with Syft, and
posts package evidence to /api/v1/serverless-packages:report.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cli, err := resolveClient(cmd.Context(), *serverFlag)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			loadOpts := []func(*awsconfig.LoadOptions) error{}
			if region != "" {
				loadOpts = append(loadOpts, awsconfig.WithRegion(region))
			}
			awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
			if err != nil {
				return fmt.Errorf("load AWS config: %w", err)
			}
			if awsCfg.Region == "" {
				return fmt.Errorf("AWS region not resolved; pass --region or set AWS_REGION")
			}
			opts := awslambda.Options{
				Region:              awsCfg.Region,
				FunctionName:        functionName,
				Qualifier:           qualifier,
				IncludeVersions:     includeVersions,
				IncludeLayers:       includeLayers,
				IncludeRoleAnalysis: analyzeRolePermissions,
				RoleAnalyzer:        awslambda.IAMRoleAnalyzer{Client: iam.NewFromConfig(awsCfg)},
				Limit:               limit,
				SourceType:          "discoverer",
				SourceRef:           sourceRef,
				PackageSource:       "syft",
				TempDir:             tempDir,
				MaxZipBytes:         maxZipMB << 20,
				MaxExtractedBytes:   maxExtractedMB << 20,
			}
			summary, collectErr := awslambda.Collect(
				ctx,
				lambda.NewFromConfig(awsCfg),
				awslambda.HTTPDownloader{},
				awslambda.SyftCataloger{Binary: syftBinary, Timeout: timeout},
				awsLambdaPackageReporter{client: cli},
				opts,
			)
			return writeServerlessSummary(cmd, summary, jsonOut, collectErr)
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "AWS region; defaults to AWS SDK configuration")
	cmd.Flags().StringVar(&functionName, "function", "", "Single Lambda function name, ARN, version, or alias to sync")
	cmd.Flags().StringVar(&qualifier, "qualifier", "", "Version or alias qualifier for --function")
	cmd.Flags().BoolVar(&includeVersions, "include-versions", false, "List all published versions when syncing every function")
	cmd.Flags().BoolVar(&includeLayers, "include-layers", true, "Download and catalog Lambda layers referenced by each function")
	cmd.Flags().BoolVar(&analyzeRolePermissions, "analyze-role-permissions", true, "Inspect the Lambda execution role's IAM policies and report permission risk metadata")
	cmd.Flags().IntVar(&limit, "limit", 0, "Maximum functions to sync; 0 means all")
	cmd.Flags().StringVar(&sourceRef, "source-ref", "", "Override scan target source_ref")
	cmd.Flags().StringVar(&syftBinary, "syft-binary", "syft", "Syft binary path")
	cmd.Flags().StringVar(&tempDir, "temp-dir", "", "Directory for temporary Lambda ZIP extraction")
	cmd.Flags().DurationVar(&timeout, "timeout", 20*time.Minute, "Overall sync timeout")
	cmd.Flags().Int64Var(&maxZipMB, "max-zip-mb", 512, "Maximum deployment or layer ZIP size in MiB")
	cmd.Flags().Int64Var(&maxExtractedMB, "max-extracted-mb", 1024, "Maximum extracted size per deployment or layer in MiB")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON summary")
	return cmd
}

type awsLambdaPackageReporter struct {
	client *authedClient
}

func (r awsLambdaPackageReporter) Report(ctx context.Context, payload awslambda.PackageReport) (awslambda.ReportResponse, error) {
	var out awslambda.ReportResponse
	if r.client == nil {
		return out, fmt.Errorf("constellation client required")
	}
	if err := r.client.postJSON(ctx, "/api/v1/serverless-packages:report", payload, &out); err != nil {
		return out, err
	}
	return out, nil
}

func writeServerlessSummary(cmd *cobra.Command, summary awslambda.Summary, jsonOut bool, collectErr error) error {
	output := &commandOutput{ctx: cmd.Context(), writer: cmd.OutOrStdout()}
	if jsonOut {
		raw, err := json.MarshalIndent(map[string]any{
			"discovered":     summary.Discovered,
			"reported":       summary.Reported,
			"skipped":        summary.Skipped,
			"failed":         summary.Failed,
			"package_count":  summary.PackageCount,
			"function_names": summary.FunctionNames,
			"errors":         summary.Errors,
		}, "", "  ")
		if err != nil {
			return errors.Join(collectErr, err)
		}
		output.println(string(raw))
	} else {
		output.printf("discovered=%d reported=%d skipped=%d failed=%d packages=%d\n",
			summary.Discovered, summary.Reported, summary.Skipped, summary.Failed, summary.PackageCount)
		if err := output.result(); err != nil {
			return errors.Join(collectErr, err)
		}
		diagnostics := &commandOutput{ctx: cmd.Context(), writer: cmd.ErrOrStderr()}
		for _, errText := range summary.Errors {
			diagnostics.printf("error: %s\n", errText)
		}
		return errors.Join(collectErr, diagnostics.result())
	}
	return errors.Join(collectErr, output.result())
}
