package dlp

import "testing"

func TestDlpSensor_Validate(t *testing.T) {
	cases := []struct {
		s    DlpSensor
		want bool
	}{
		{DlpSensor{Name: ""}, true},
		{DlpSensor{Name: "n", CfgType: "wat"}, true},
		{DlpSensor{Name: "n", CfgType: CfgUser, Rules: []DlpRule{{Name: "", Pattern: ".*", Context: ContextBody, Action: ActionAlert}}}, true},
		{DlpSensor{Name: "n", CfgType: CfgUser, Rules: []DlpRule{{Name: "r", Pattern: "[bad", Context: ContextBody, Action: ActionAlert}}}, true},
		{DlpSensor{Name: "n", CfgType: CfgUser, Rules: []DlpRule{{Name: "r", Pattern: ".*", Context: "wat", Action: ActionAlert}}}, true},
		{DlpSensor{Name: "n", CfgType: CfgUser, Rules: []DlpRule{{Name: "r", Pattern: ".*", Context: ContextBody, Action: "wat"}}}, true},
		{DlpSensor{Name: "ok", CfgType: CfgUser, Rules: []DlpRule{{Name: "r", Pattern: ".*", Context: ContextBody, Action: ActionAlert}}}, false},
	}
	for i, c := range cases {
		err := c.s.Validate()
		if (err != nil) != c.want {
			t.Errorf("case %d: gotErr=%v want=%v", i, err, c.want)
		}
	}
}

func TestDefaultCatalog_AllValid(t *testing.T) {
	for _, s := range DefaultCatalog() {
		if err := s.Validate(); err != nil {
			t.Errorf("seed sensor %s invalid: %v", s.Name, err)
		}
	}
}
