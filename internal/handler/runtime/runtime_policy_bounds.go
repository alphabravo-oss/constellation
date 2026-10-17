package runtime

import (
	"encoding/json"
	"errors"
	"math"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

func policyWireID(id int64) (uint32, error) {
	if id < 0 || id > math.MaxUint32 {
		return 0, errors.New("policy identity exceeds the dataplane wire range")
	}
	return uint32(id), nil
}

func policyDirection(direction int) (int16, error) {
	// Zero is retained for legacy rows; authored defaults are ApplyDirBoth.
	if direction < 0 || direction > dp.ApplyDirBoth {
		return 0, errors.New("apply_dir must be between 0 and 3")
	}
	return int16(direction), nil
}

func validatePolicyPatch(action *uint8, direction *int, rules *json.RawMessage) error {
	if action != nil && *action > dp.PolicyActionDeny {
		return errors.New("def_action is not a supported dataplane action")
	}
	if direction != nil {
		if _, err := policyDirection(*direction); err != nil {
			return err
		}
	}
	if rules != nil {
		_, err := (&RuntimePolicy{Rules: *rules}).DecodeRules()
		return err
	}
	return nil
}

func policyDatabaseDirection(p *RuntimePolicy) (int16, error) {
	if err := validatePolicyPatch(&p.DefAction, &p.ApplyDir, &p.Rules); err != nil {
		return 0, err
	}
	return policyDirection(p.ApplyDir)
}
