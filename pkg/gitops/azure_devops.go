package gitops

// Azure DevOps push connector — commits a file via the Azure DevOps Git Push API.
// Modeled on NeuVector's controller/remote_repository/azure_devops.go: resolve the target
// branch ref (for its objectId), then POST a push that "add"s the file, retrying as an
// "edit" when the path already exists. Rewritten to Constellation style (context-aware
// requests, structured errors, injectable client).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const azureAPIURLFmt = "https://dev.azure.com/%s/%s/_apis/git/repositories/%s/%s?api-version=6.0"

const (
	azurePushOpAdd  = "add"
	azurePushOpEdit = "edit"
)

// errAzureFileExists signals the "add" collided with an existing path; retry as "edit".
var errAzureFileExists = errors.New("gitops: azure file already exists at path")

type azureRefsResponse struct {
	Value []azureRef `json:"value"`
}

type azureRef struct {
	Name     string `json:"name"`
	ObjectID string `json:"objectId"`
}

func (r azureRef) branch() string {
	parts := strings.Split(r.Name, "/")
	return parts[len(parts)-1]
}

type azurePushRequest struct {
	RefUpdates []azureRefUpdate `json:"refUpdates"`
	Commits    []azureCommit    `json:"commits"`
}

type azureRefUpdate struct {
	Name        string `json:"name"`
	OldObjectID string `json:"oldObjectId"`
}

type azureCommit struct {
	Comment string        `json:"comment"`
	Changes []azureChange `json:"changes"`
}

type azureChange struct {
	ChangeType string          `json:"changeType"`
	Item       azureItem       `json:"item"`
	NewContent azureNewContent `json:"newContent"`
}

type azureItem struct {
	Path string `json:"path"`
}

type azureNewContent struct {
	Content     string `json:"content"`
	ContentType string `json:"contentType"`
}

// pushAzureDevops creates-or-updates cfg.FilePath on cfg.Branch with fileContents.
func pushAzureDevops(ctx context.Context, cfg ConnectorConfig, fileContents []byte, message string) error {
	ref, err := azureGetRef(ctx, cfg)
	if err != nil {
		return fmt.Errorf("gitops: azure get ref: %w", err)
	}
	err = azurePush(ctx, cfg, ref, azurePushOpAdd, fileContents, message)
	if errors.Is(err, errAzureFileExists) {
		err = azurePush(ctx, cfg, ref, azurePushOpEdit, fileContents, message)
	}
	if err != nil {
		return fmt.Errorf("gitops: azure push: %w", err)
	}
	return nil
}

func azureGetRef(ctx context.Context, cfg ConnectorConfig) (azureRef, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, azureURL(cfg, "refs"), nil)
	if err != nil {
		return azureRef{}, err
	}
	req.SetBasicAuth("", cfg.PAT)
	resp, err := cfg.httpClient().Do(req)
	if err != nil {
		return azureRef{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return azureRef{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var refs azureRefsResponse
	if err := json.NewDecoder(resp.Body).Decode(&refs); err != nil {
		return azureRef{}, fmt.Errorf("decode refs: %w", err)
	}
	for _, r := range refs.Value {
		if r.branch() == cfg.Branch {
			return r, nil
		}
	}
	return azureRef{}, fmt.Errorf("branch %q not found", cfg.Branch)
}

func azurePush(ctx context.Context, cfg ConnectorConfig, ref azureRef, op string, fileContents []byte, message string) error {
	path := cfg.FilePath
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	body := azurePushRequest{
		RefUpdates: []azureRefUpdate{{Name: ref.Name, OldObjectID: ref.ObjectID}},
		Commits: []azureCommit{{
			Comment: message,
			Changes: []azureChange{{
				ChangeType: op,
				Item:       azureItem{Path: path},
				NewContent: azureNewContent{Content: string(fileContents), ContentType: "rawtext"},
			}},
		}},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal push: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, azureURL(cfg, "pushes"), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("", cfg.PAT)
	resp, err := cfg.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		return nil
	}
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode == http.StatusBadRequest && strings.Contains(string(snippet), "already exists") {
		return errAzureFileExists
	}
	return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(snippet))
}

func azureURL(cfg ConnectorConfig, endpoint string) string {
	return fmt.Sprintf(azureAPIURLFmt, cfg.AzureOrg, cfg.AzureProject, cfg.AzureRepo, endpoint)
}
