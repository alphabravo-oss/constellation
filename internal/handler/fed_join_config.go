package handler

import (
	"errors"
	"net/url"
	"strings"
)

// A deployment join token belongs to its configured master destination, not to
// any URL an organization administrator supplies in a join request.
func resolveRemoteJoinConfig(req fedJoinRemoteRequest, configuredURL, configuredToken string) (string, string, error) {
	master, err := normalizeRemoteMaster(firstNonEmpty(req.MasterURL, configuredURL))
	if err != nil {
		return "", "", err
	}
	token := req.Token
	if token == "" {
		configuredMaster, configErr := normalizeRemoteMaster(configuredURL)
		if configErr != nil || master != configuredMaster {
			return "", "", errors.New("federation: an explicit token is required when overriding the configured master URL")
		}
		token = configuredToken
	}
	if strings.TrimSpace(token) == "" {
		return "", "", errors.New("federation: token is required (body or configured master token)")
	}
	return master, token, nil
}

func normalizeRemoteMaster(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return "", errors.New("federation: master endpoint must be an absolute HTTPS URL without credentials, query or fragment")
	}
	endpoint.Host = strings.ToLower(endpoint.Host)
	return endpoint.String(), nil
}
