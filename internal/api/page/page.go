// Package page validates bounded offset pages for administrative inventories.
package page

import (
	"fmt"
	"net/url"
	"strconv"
)

type Options struct{ Limit, Offset int }

func Parse(values url.Values) (Options, error) {
	out := Options{Limit: 100}
	for _, field := range []struct {
		name string
		dest *int
		max  int
	}{{"limit", &out.Limit, 500}, {"offset", &out.Offset, 2147483647}} {
		raw, present := values[field.name]
		if !present {
			continue
		}
		if len(raw) != 1 {
			return out, fmt.Errorf("duplicate %s", field.name)
		}
		n, err := strconv.Atoi(raw[0])
		if err != nil || n < 0 || n > field.max || field.name == "limit" && n == 0 {
			return out, fmt.Errorf("invalid %s", field.name)
		}
		*field.dest = n
	}
	return out, nil
}
