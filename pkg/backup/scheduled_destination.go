package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ValidateScheduleDestination rejects incomplete or unsafe object destinations
// before the API persists a schedule. An entirely empty destination means local.
func ValidateScheduleDestination(bucket, prefix, endpoint string) error {
	_, err := scheduleDestination(schedule{S3Bucket: bucket, S3Prefix: prefix, S3Endpoint: endpoint}, "validation.tar.gz")
	return err
}

func scheduleDestination(s schedule, name string) (string, error) {
	if s.S3Bucket == "" {
		if s.S3Prefix != "" || s.S3Endpoint != "" {
			return "", errors.New("backup destination requires a bucket")
		}
		return "", nil
	}
	if strings.Contains(s.S3Bucket, "/") {
		return "", errors.New("invalid backup bucket")
	}
	if err := ValidateS3Endpoint(s.S3Endpoint); err != nil {
		return "", err
	}
	return S3ArtifactURI("s3://"+s.S3Bucket+"/"+s.S3Prefix, name)
}

// A scheduled remote backup succeeds only after reading back the exact bytes.
// Unique catalog IDs provide object identity. Remote deletion is intentionally
// left to a separately configured bucket lifecycle; the catalog receipt remains.
func uploadScheduledArtifact(ctx context.Context, uri, endpoint, path string, size int64) (string, error) {
	file, err := OpenArtifact(path)
	if err != nil {
		return "", CLIFailure("open scheduled backup", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size || size < 0 || size > 5*1024*1024*1024 {
		return "", errors.New("scheduled backup requires an unchanged regular artifact at most 5 GiB")
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", CLIFailure("hash scheduled backup", err)
	}
	expected := hex.EncodeToString(hash.Sum(nil))
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return "", CLIFailure("rewind scheduled backup", err)
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return "", CLIFailure("backup object credentials", err)
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = true
		}
	})
	bucket, key, _ := strings.Cut(strings.TrimPrefix(uri, "s3://"), "/")
	_, err = client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: file, ContentLength: aws.Int64(size)})
	if err != nil {
		return "", CLIFailure("scheduled backup upload", err)
	}
	result, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return "", CLIFailure("scheduled backup read-back", err)
	}
	defer func() { _ = result.Body.Close() }()
	hash.Reset()
	count, err := io.Copy(hash, io.LimitReader(result.Body, size+1))
	if err != nil {
		return "", CLIFailure("scheduled backup read-back", err)
	}
	if count != size || hex.EncodeToString(hash.Sum(nil)) != expected {
		return "", errors.New("scheduled backup read-back mismatch")
	}
	return expected, nil
}
