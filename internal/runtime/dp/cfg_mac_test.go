package dp

import (
	"encoding/json"
	"testing"
)

// TestParseListenPorts checks that only LISTEN sockets (st == 0x0A) are picked
// up and their hex local ports decoded, matching the /proc/<pid>/net/tcp layout
// per proc(5). Non-LISTEN states and malformed lines are ignored.
func TestParseListenPorts(t *testing.T) {
	// Columns: sl local_address rem_address st ...
	// 0x0050 = 80, 0x1F90 = 8080, 0x0016 = 22. The ESTABLISHED (01) row for
	// port 0x1234 must be skipped; only LISTEN (0A) rows count.
	table := []byte(
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
			"   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1\n" +
			"   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2\n" +
			"   2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3\n" +
			"   3: 0100007F:1234 0100007F:9999 01 00000000:00000000 00:00000000 00000000     0        0 4\n" +
			"   4: garbageline\n",
	)
	got := parseListenPorts(table)
	want := map[uint16]bool{80: true, 8080: true, 22: true}
	if len(got) != len(want) {
		t.Fatalf("parseListenPorts = %v, want ports %v", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected port %d in %v", p, got)
		}
	}
}

// TestCfgMACWire pins the ctrl_cfg_mac JSON exactly to what dp_ctrl_cfg_mac
// reads (third_party/neuvector/dp/ctrl.c:680-725): top key "ctrl_cfg_mac" with
// "macs"/"tap"/"apps", and each app carrying port/ip_proto/app/server. A drift
// here silently breaks parser recruitment (dp would ignore the message).
func TestCfgMACWire(t *testing.T) {
	tap := true
	req := &cfgMACReq{Cfg: &macConfig{
		MACs: []string{"aa:bb:cc:00:00:01"},
		Tap:  &tap,
		Apps: []protoPortApp{{Port: 80, IPProto: 6}},
	}}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"ctrl_cfg_mac":{"macs":["aa:bb:cc:00:00:01"],"tap":true,"apps":[{"port":80,"ip_proto":6,"app":0,"server":0}]}}`
	if string(b) != want {
		t.Fatalf("ctrl_cfg_mac wire mismatch:\n got: %s\nwant: %s", b, want)
	}

	// tap and apps are omitted when unset, so a bare MAC config marshals clean.
	bare, err := json.Marshal(&cfgMACReq{Cfg: &macConfig{MACs: []string{"aa:bb:cc:00:00:01"}}})
	if err != nil {
		t.Fatalf("marshal bare: %v", err)
	}
	const wantBare = `{"ctrl_cfg_mac":{"macs":["aa:bb:cc:00:00:01"]}}`
	if string(bare) != wantBare {
		t.Fatalf("bare ctrl_cfg_mac wire mismatch:\n got: %s\nwant: %s", bare, wantBare)
	}
}
