package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// stringList is a request field holding a list of strings, accepted as Vault
// accepts it: a JSON array, or one comma-separated string ("a,b"). Entries are
// trimmed and empty ones dropped.
type stringList []string

func (l *stringList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*l = splitList(strings.Split(s, ","))
		return nil
	}
	var items []string
	if err := json.Unmarshal(b, &items); err != nil {
		return errors.New("must be a list of strings or a comma-separated string")
	}
	*l = splitList(items)
	return nil
}

func splitList(items []string) stringList {
	out := stringList{}
	for _, s := range items {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
