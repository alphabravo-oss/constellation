package runtime

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strconv"
)

func baselineInventoryCSV(items []baselineInventoryRow) ([]byte, error) {
	var body bytes.Buffer
	w := csv.NewWriter(&body)
	if err := w.Write([]string{"Profile ID", "Cluster", "Workload", "Namespace", "Name", "Mode", "Configured", "Owner count", "Ambiguous owners", "Platform role", "Processes (retained)", "Alerts (retained 24h)", "Blocks (retained 24h)", "Configured rules", "Learn started", "Monitor started", "Enforce started", "Last new process (retained)", "Top processes (JSON)"}); err != nil {
		return nil, err
	}
	for _, p := range items {
		top, _ := json.Marshal(p.TopProcesses)
		if err := w.Write([]string{p.RowID, p.ClusterID, p.WorkloadID, p.Namespace, p.Name, p.Mode, strconv.FormatBool(p.Configured), strconv.Itoa(p.OwnerCount), strconv.FormatBool(p.OwnerAmbiguous), p.PlatformRole, strconv.Itoa(p.LearnedProcessesCount), strconv.Itoa(p.MonitoredAlerts24h), strconv.Itoa(p.EnforcedBlocks24h), strconv.Itoa(p.RuleCount), p.LearnStartedAt, p.MonitorStartedAt, p.EnforceStartedAt, p.LastNewProcessAt, string(top)}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return body.Bytes(), w.Error()
}
