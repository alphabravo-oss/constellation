package handler

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type timelineWindow struct {
	from, to                         time.Time
	lowerOnly, exclusive, upperBound bool
}

func parseTimelineWindow(q url.Values, now time.Time) (timelineWindow, error) {
	window := timelineWindow{to: now.Add(time.Minute), upperBound: true}
	window.from = window.to.Add(-7 * 24 * time.Hour)
	if q.Get("after") != "" && q.Get("hours") != "" {
		return window, fmt.Errorf("choose after or hours, not both")
	}
	if q.Get("after") != "" || q.Get("hours") != "" {
		if q.Get("from") != "" || q.Get("to") != "" {
			return window, fmt.Errorf("after/hours cannot be combined with from/to")
		}
		window.lowerOnly, window.upperBound = true, false
		if value := q.Get("after"); value != "" {
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return window, fmt.Errorf("invalid after (want RFC3339)")
			}
			window.from = parsed
		} else {
			hours, err := strconv.Atoi(q.Get("hours"))
			if err != nil || hours < 1 || hours > 2160 {
				return window, fmt.Errorf("hours must be between 1 and 2160")
			}
			window.from = now.Add(-time.Duration(hours) * time.Hour)
		}
	}
	for _, name := range []string{"from", "to"} {
		if value := q.Get(name); value != "" {
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return window, fmt.Errorf("invalid %s (want RFC3339)", name)
			}
			if name == "from" {
				window.from = parsed
			} else {
				window.to = parsed
			}
		}
	}
	if value := q.Get("after_exclusive"); value != "" {
		if value != "true" && value != "false" {
			return window, fmt.Errorf("after_exclusive must be true or false")
		}
		if !window.lowerOnly {
			return window, fmt.Errorf("after_exclusive requires after or hours")
		}
		window.exclusive = value == "true"
	}
	if window.upperBound && !window.from.Before(window.to) {
		return window, fmt.Errorf("from must precede to")
	}
	return window, nil
}

func parseTimelineVerdicts(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	out := []string{}
	seen := map[string]bool{}
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		switch value {
		case "alert", "block", "quarantine", "allow", "observed", "deny":
		default:
			return nil, fmt.Errorf("invalid runtime event verdict")
		}
		if !seen[value] {
			out = append(out, value)
			seen[value] = true
		}
	}
	return out, nil
}

func parseTimelinePagination(q url.Values) (int, int, error) {
	limit := 100
	if value := q.Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 500 {
			return 0, 0, fmt.Errorf("limit must be between 1 and 500")
		}
		limit = parsed
	}
	offset := 0
	if value := q.Get("offset"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 || parsed > 1000000 {
			return 0, 0, fmt.Errorf("offset must be between 0 and 1000000")
		}
		offset = parsed
	}
	return limit, offset, nil
}
