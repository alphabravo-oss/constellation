package dp

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Meter detect/threshold config push.
//
// dp runs three flood meters — SYN flood, ICMP flood, per-source session flood
// — whose fire/clear thresholds are compiled into meter_info[] in
// third_party/neuvector/dp/dpi/dpi_meter.c. We already DECODE the resulting
// DP_KIND_METER_LIST reports (proto.go), but until now pushed no config, so the
// meters could only ever run on those compiled defaults. This adds a thin,
// additive config push over the same ctrl socket the other cfg pushes use
// (ctrl_cfg_policy / ctrl_cfg_dlp / ctrl_enable_icmp_policy), carrying a
// per-meter UpperLimit/LowerLimit/Span so the thresholds become tunable.
//
// Wire kind is `ctrl_cfg_detect`, mirroring dp's ctrl_cfg_* naming. Like
// AddNfqPort, this is a scaffold ahead of the matching dp-side handler: dp
// currently ignores an unrecognised ctrl message (logs + moves on), so pushing
// it is harmless today and becomes load-bearing once the fork grows the handler.

// meter IDs, mirrored from METER_ID_* in third_party/neuvector/defs.h. Only the
// three flood meters are tunable here; TCP_NODATA is left on its compiled default.
const (
	synFloodMeterID     uint8 = 0 // METER_ID_SYN_FLOOD
	icmpFloodMeterID    uint8 = 1 // METER_ID_ICMP_FLOOD
	ipSrcSessionMeterID uint8 = 2 // METER_ID_IP_SRC_SESSION
)

// Env overrides for the per-span fire threshold of each meter. Unset leaves the
// NV compiled default (see meterConfigFromEnv) untouched.
const (
	envMeterSynFlood  = "CONSTELLATION_METER_SYN_FLOOD"
	envMeterICMPFlood = "CONSTELLATION_METER_ICMP_FLOOD"
	envMeterSession   = "CONSTELLATION_METER_SESSION"
)

// meterThreshold is the tunable detect config for one flood meter. A meter
// counts incidents (SYN packets / ICMP packets / new sessions) per Span seconds
// and fires when the count crosses UpperLimit, clearing once it falls back below
// LowerLimit (hysteresis). Field names track meter_info_t in dpi_meter.h.
type meterThreshold struct {
	MeterID    uint8  `json:"meter_id"`
	Span       uint8  `json:"span"`
	UpperLimit uint32 `json:"upper_limit"`
	LowerLimit uint32 `json:"lower_limit"`
}

type dpMeterCfg struct {
	Meters []meterThreshold `json:"meters"`
}

type dpMeterCfgReq struct {
	Cfg *dpMeterCfg `json:"ctrl_cfg_detect"`
}

// meterConfigFromEnv builds the three-meter threshold set, seeded with NV's
// compiled baselines (meter_info[] in dpi_meter.c) and overlaid with any env
// overrides.
func meterConfigFromEnv() []meterThreshold {
	return []meterThreshold{
		meterThresholdFromEnv(envMeterSynFlood, meterThreshold{MeterID: synFloodMeterID, Span: 5, UpperLimit: 800, LowerLimit: 600}),
		meterThresholdFromEnv(envMeterICMPFlood, meterThreshold{MeterID: icmpFloodMeterID, Span: 1, UpperLimit: 100, LowerLimit: 100}),
		meterThresholdFromEnv(envMeterSession, meterThreshold{MeterID: ipSrcSessionMeterID, Span: 1, UpperLimit: 2000, LowerLimit: 2000}),
	}
}

// meterThresholdFromEnv overlays an env override onto an NV-default baseline.
// The env value is the per-span UpperLimit (the count at which the meter fires);
// an empty or unparseable value leaves the baseline untouched. When an override
// lowers UpperLimit below the baseline LowerLimit, LowerLimit is clamped down so
// the meter can still clear (LowerLimit must never exceed UpperLimit).
func meterThresholdFromEnv(env string, def meterThreshold) meterThreshold {
	v := strings.TrimSpace(os.Getenv(env))
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil || n == 0 {
		return def
	}
	def.UpperLimit = uint32(n)
	if def.LowerLimit > def.UpperLimit {
		def.LowerLimit = def.UpperLimit
	}
	return def
}

// setMeterConfig pushes the meter threshold set to dp over the ctrl socket.
// Fire-and-forget, like the other cfg pushes.
func (c *dpClient) setMeterConfig(meters []meterThreshold) error {
	return c.sendOneway(&dpMeterCfgReq{Cfg: &dpMeterCfg{Meters: meters}})
}

// PushMeterConfig sends the flood-meter detect/threshold config (read from env,
// NV defaults as baseline) to dp. Additive: until it is called the meters run on
// their compiled defaults exactly as before. Send it once after Start, alongside
// SetICMPPolicy — dp holds the config globally.
func (s *Supervisor) PushMeterConfig() error {
	if s == nil || s.client == nil {
		return fmt.Errorf("dp meter: supervisor not started")
	}
	return s.client.setMeterConfig(meterConfigFromEnv())
}
