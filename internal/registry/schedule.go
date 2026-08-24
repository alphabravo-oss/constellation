package registry

import (
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

// ScheduleMode controls when the registry walker re-syncs a registry. It generalizes the
// single global WALKER_INTERVAL into three per-registry modes.
type ScheduleMode string

const (
	// ScheduleManual: never auto-synced. The registry is only walked on an explicit,
	// operator-triggered sync.
	ScheduleManual ScheduleMode = "manual"

	// ScheduleAuto: synced on every walker tick using the daemon's global interval. Use
	// for registries that should track the platform-wide default cadence without pinning
	// a fixed period.
	ScheduleAuto ScheduleMode = "auto"

	// SchedulePeriodic: synced on a per-registry fixed interval (e.g. hourly/daily),
	// independent of the global tick rate.
	SchedulePeriodic ScheduleMode = "periodic"

	// ScheduleCron: synced when a five-field cron expression reaches its next fire time.
	ScheduleCron ScheduleMode = "cron"
)

// Schedule is the resolved per-registry sync schedule.
type Schedule struct {
	Mode ScheduleMode
	// Interval is the fixed period for SchedulePeriodic. Ignored for manual/auto.
	Interval time.Duration
	// CronExpr is the five-field cron expression for ScheduleCron.
	CronExpr string
}

// cadenceIntervals maps the stored scan_cadence keyword to its periodic interval.
var cadenceIntervals = map[string]time.Duration{
	"hourly": time.Hour,
	"6h":     6 * time.Hour,
	"daily":  24 * time.Hour,
	"weekly": 7 * 24 * time.Hour,
}

// ResolveSchedule maps a stored cadence keyword to a Schedule. Recognized keywords:
//
//	"manual"                          -> ScheduleManual
//	"auto"                            -> ScheduleAuto
//	"hourly" | "6h" | "daily" | "weekly" -> SchedulePeriodic with the matching interval
//	a Go duration ("15m", "2h30m")    -> SchedulePeriodic with that interval
//	"cron:<expr>"                     -> ScheduleCron with a five-field cron expression
//
// Anything unrecognized resolves to ScheduleManual (fail closed: don't auto-walk a
// registry whose cadence we can't interpret).
func ResolveSchedule(cadence string) Schedule {
	c := strings.ToLower(strings.TrimSpace(cadence))
	switch c {
	case "", "manual":
		return Schedule{Mode: ScheduleManual}
	case "auto":
		return Schedule{Mode: ScheduleAuto}
	}
	if d, ok := cadenceIntervals[c]; ok {
		return Schedule{Mode: SchedulePeriodic, Interval: d}
	}
	if d, err := time.ParseDuration(c); err == nil && d > 0 {
		return Schedule{Mode: SchedulePeriodic, Interval: d}
	}
	if expr, ok := strings.CutPrefix(c, "cron:"); ok {
		expr = strings.TrimSpace(expr)
		if _, err := cronParser().Parse(expr); err == nil {
			return Schedule{Mode: ScheduleCron, CronExpr: expr}
		}
	}
	return Schedule{Mode: ScheduleManual}
}

// IsDue reports whether a registry is due for sync now.
//
//   - manual:   never due.
//   - auto:     due once at least globalInterval has elapsed since lastSync (and always
//     due when never synced). This lets every walker tick consider auto registries while
//     still respecting the daemon's minimum cadence.
//   - periodic: due once the registry's own Interval has elapsed since lastSync (always
//     due when never synced).
//   - cron:     due when the next cron occurrence after lastSync is at or before now.
//
// lastSync is nil when the registry has never been synced.
func (s Schedule) IsDue(lastSync *time.Time, now time.Time, globalInterval time.Duration) bool {
	switch s.Mode {
	case ScheduleManual:
		return false
	case ScheduleAuto:
		if lastSync == nil {
			return true
		}
		if globalInterval <= 0 {
			return true
		}
		return now.Sub(*lastSync) >= globalInterval
	case SchedulePeriodic:
		if s.Interval <= 0 {
			return false
		}
		if lastSync == nil {
			return true
		}
		return now.Sub(*lastSync) >= s.Interval
	case ScheduleCron:
		if s.CronExpr == "" {
			return false
		}
		if lastSync == nil {
			return true
		}
		sched, err := cronParser().Parse(s.CronExpr)
		if err != nil {
			return false
		}
		next := sched.Next(*lastSync)
		return !next.After(now)
	default:
		return false
	}
}

func cronParser() cron.Parser {
	return cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
}
