package storagehealth

import "github.com/alphabravocompany/constellation/internal/auditarchive"

// ArchiveDestination mirrors the publisher's nonempty endpoint precedence,
// including endpoints resolved from Kubernetes Secret references at runtime.
type ArchiveDestination struct {
	Enabled                                               bool
	Endpoint, EndpointS3, EndpointDefault, Bucket, Prefix string
}

func (c ArchiveDestination) StreamID() string {
	if !c.Enabled {
		return ""
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = c.EndpointS3
	}
	if endpoint == "" {
		endpoint = c.EndpointDefault
	}
	return auditarchive.DestinationID(endpoint, c.Bucket, c.Prefix)
}
