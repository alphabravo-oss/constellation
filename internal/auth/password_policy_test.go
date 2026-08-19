package auth

import (
	"errors"
	"testing"
)

// A4: ValidatePassword rejects weak/empty passwords and accepts ones that meet the
// default profile. Table-driven over (candidate) -> accept/reject.
func TestValidatePassword(t *testing.T) {
	profile := DefaultPasswordProfile() // 12+ chars, >=3 classes

	cases := []struct {
		name    string
		pw      string
		wantErr bool
	}{
		{"empty", "", true},
		{"whitespace only", "            ", true},
		{"too short", "Ab1!xyz", true},
		{"long but one class", "aaaaaaaaaaaaaaaa", true},
		{"long but two classes", "aaaaaaaaaaaa1111", true},
		{"three classes ok", "Password1234", false},
		{"four classes ok", "Password-1234!", false},
		{"exactly min length three classes", "Abcdefghij1!", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassword(profile, tc.pw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidatePassword(%q) = nil, want error", tc.pw)
				}
				if !errors.Is(err, ErrWeakPassword) {
					t.Fatalf("ValidatePassword(%q) error = %v, want ErrWeakPassword", tc.pw, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidatePassword(%q) = %v, want nil", tc.pw, err)
			}
		})
	}
}
