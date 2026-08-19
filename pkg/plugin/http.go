package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// HTTPInfo fetches the plugin manifest. Wire path: GET <endpoint>/v1/plugin/info.
func (c *Client) HTTPInfo(ctx context.Context) (Manifest, error) {
	body, err := c.do(ctx, http.MethodGet, "/v1/plugin/info", nil)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return Manifest{}, err
	}
	m.Endpoint = c.Endpoint
	return m, nil
}

// HTTPScan invokes a Scanner plugin over HTTP. Wire path: POST <endpoint>/v1/plugin/scan.
func (c *Client) HTTPScan(ctx context.Context, req ScanRequest) (ScanResult, error) {
	body, err := c.do(ctx, http.MethodPost, "/v1/plugin/scan", req)
	if err != nil {
		return ScanResult{}, err
	}
	var r ScanResult
	if err := json.Unmarshal(body, &r); err != nil {
		return ScanResult{}, err
	}
	return r, nil
}

// HTTPEnrich invokes an Enricher plugin.
func (c *Client) HTTPEnrich(ctx context.Context, in []Finding) ([]Finding, error) {
	body, err := c.do(ctx, http.MethodPost, "/v1/plugin/enrich", in)
	if err != nil {
		return nil, err
	}
	var out []Finding
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// HTTPExport invokes an Exporter plugin.
func (c *Client) HTTPExport(ctx context.Context, in []Finding) (Receipt, error) {
	body, err := c.do(ctx, http.MethodPost, "/v1/plugin/export", in)
	if err != nil {
		return Receipt{}, err
	}
	var r Receipt
	if err := json.Unmarshal(body, &r); err != nil {
		return Receipt{}, err
	}
	return r, nil
}

func (c *Client) do(ctx context.Context, method, path string, in any) ([]byte, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Endpoint+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("plugin: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("plugin: %s %s status %d: %s", method, path, resp.StatusCode, out)
	}
	return out, nil
}
