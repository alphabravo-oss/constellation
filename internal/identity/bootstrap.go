package identity

import "context"

func (s *Service) bootstrap(ctx context.Context, c LocalConfig) error {
	return s.store.bootstrap(ctx, c, s.emergency, s.enc, s.audit)
}
