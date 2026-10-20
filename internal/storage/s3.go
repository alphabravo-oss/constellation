// Package storage is the S3 client wrapper the guide prescribes (ch.09): every
// object-store consumer goes through an S3-API client (MinIO SDK) against a
// discovered endpoint (explicit config > Kubernetes Service discovery), with a
// second client for presigned URLs when the externally reachable endpoint
// differs, idle-connection tolerance, and an idempotent bucket create.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Config describes one bucket on one S3-compatible store.
type Config struct {
	// Endpoint is host[:port]; empty means discover via Discovery.
	Endpoint string
	// PresignEndpoint is the host[:port] clients outside the cluster reach;
	// empty means presigned URLs use Endpoint.
	PresignEndpoint string
	Bucket          string
	Region          string
	AccessKey       string
	SecretKey       string
	UseSSL          bool
	// Discovery resolves Endpoint from a Kubernetes Service when Endpoint is empty.
	Discovery *Discovery
}

// Client is a bucket-scoped S3 client.
type Client struct {
	s3       *minio.Client
	presign  *minio.Client
	bucket   string
	endpoint string
}

// ErrNoEndpoint is returned when neither Endpoint nor Discovery yields an address.
var ErrNoEndpoint = errors.New("storage: no endpoint configured or discovered")

// New resolves the endpoint, builds the clients and ensures the bucket exists.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("storage: Bucket is required")
	}
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		if cfg.Discovery == nil {
			return nil, ErrNoEndpoint
		}
		ep, err := cfg.Discovery.Resolve(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrNoEndpoint, err)
		}
		endpoint = ep
	}
	endpoint, useSSL := splitScheme(endpoint, cfg.UseSSL)
	creds := credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, "")
	opts := func() *minio.Options {
		return &minio.Options{Creds: creds, Secure: useSSL, Region: cfg.Region, Transport: transport()}
	}
	s3, err := minio.New(endpoint, opts())
	if err != nil {
		return nil, fmt.Errorf("storage: client: %w", err)
	}
	c := &Client{s3: s3, presign: s3, bucket: cfg.Bucket, endpoint: endpoint}
	if pe := strings.TrimSpace(cfg.PresignEndpoint); pe != "" && pe != endpoint {
		pe, pssl := splitScheme(pe, cfg.UseSSL)
		po := opts()
		po.Secure = pssl
		if c.presign, err = minio.New(pe, po); err != nil {
			return nil, fmt.Errorf("storage: presign client: %w", err)
		}
	}
	if err := c.EnsureBucket(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// Endpoint is the resolved host[:port].
func (c *Client) Endpoint() string { return c.endpoint }

// Bucket is the configured bucket.
func (c *Client) Bucket() string { return c.bucket }

// EnsureBucket creates the bucket when it is missing; a concurrent creator
// winning the race is not an error.
func (c *Client) EnsureBucket(ctx context.Context) error {
	exists, err := c.s3.BucketExists(ctx, c.bucket)
	if err != nil {
		return fmt.Errorf("storage: bucket exists: %w", err)
	}
	if exists {
		return nil
	}
	if err := c.s3.MakeBucket(ctx, c.bucket, minio.MakeBucketOptions{}); err != nil {
		var mr minio.ErrorResponse
		if errors.As(err, &mr) && (mr.Code == "BucketAlreadyOwnedByYou" || mr.Code == "BucketAlreadyExists") {
			return nil
		}
		return fmt.Errorf("storage: make bucket: %w", err)
	}
	return nil
}

// Put uploads an object. size may be -1 when unknown.
func (c *Client) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	_, err := c.s3.PutObject(ctx, c.bucket, key, r, size, minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return fmt.Errorf("storage: put %s: %w", key, err)
	}
	return nil
}

// Get streams an object; the caller closes the reader.
func (c *Client) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	obj, err := c.s3.GetObject(ctx, c.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("storage: get %s: %w", key, err)
	}
	if _, err := obj.Stat(); err != nil {
		_ = obj.Close()
		return nil, fmt.Errorf("storage: get %s: %w", key, err)
	}
	return obj, nil
}

// Delete removes an object (idempotent).
func (c *Client) Delete(ctx context.Context, key string) error {
	if err := c.s3.RemoveObject(ctx, c.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("storage: delete %s: %w", key, err)
	}
	return nil
}

// List returns object keys under prefix.
func (c *Client) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	for obj := range c.s3.ListObjects(ctx, c.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("storage: list %s: %w", prefix, obj.Err)
		}
		keys = append(keys, obj.Key)
	}
	return keys, nil
}

// PresignGet returns a time-limited download URL built with the presign
// client, so it carries the externally reachable host.
func (c *Client) PresignGet(ctx context.Context, key string, ttl time.Duration) (*url.URL, error) {
	u, err := c.presign.PresignedGetObject(ctx, c.bucket, key, ttl, nil)
	if err != nil {
		return nil, fmt.Errorf("storage: presign %s: %w", key, err)
	}
	return u, nil
}

// transport tolerates stores that close idle connections early (RustFS,
// MinIO behind proxies): short idle timeout, bounded per-host idle pool, and
// the SDK's own retry on connection reset.
func transport() http.RoundTripper {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       20 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
	}
}

func splitScheme(endpoint string, useSSL bool) (string, bool) {
	switch {
	case strings.HasPrefix(endpoint, "https://"):
		return strings.TrimPrefix(endpoint, "https://"), true
	case strings.HasPrefix(endpoint, "http://"):
		return strings.TrimPrefix(endpoint, "http://"), false
	}
	return strings.TrimSuffix(endpoint, "/"), useSSL
}
