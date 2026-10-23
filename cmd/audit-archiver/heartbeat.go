package main

import (
	"strings"
)

type auditArchiveHeartbeatState struct {
	Bucket        string
	Prefix        string
	DryRun        bool
	SignMode      string
	Stage         string
	RecordCount   int64
	ArchiveKey    string
	ManifestKey   string
	Success       bool
	LastErrorText string
}

func (s *auditArchiveHeartbeatState) snapshot() any {
	return map[string]any{
		"bucket_configured": strings.TrimSpace(s.Bucket) != "",
		"prefix":            s.Prefix,
		"dry_run":           s.DryRun,
		"sign_mode":         s.SignMode,
		"stage":             s.Stage,
		"record_count":      s.RecordCount,
		"archive_key":       s.ArchiveKey,
		"manifest_key":      s.ManifestKey,
		"success":           s.Success,
	}
}

func (s *auditArchiveHeartbeatState) lastError() string {
	return s.LastErrorText
}
