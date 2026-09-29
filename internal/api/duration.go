package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
)

// vaultDuration is a request field holding a duration, accepted in every form
// Vault accepts: a Go duration string ("1h", "90m"), a string of whole seconds
// ("3600"), or a JSON number of seconds (3600). Vault's own client sends numbers
// (e.g. renew-self's increment), people and curl examples send strings. It is
// normalized to a Go duration string ("3600s"), so existing parsing and
// validation of the value are unchanged; "" still means "not set".
type vaultDuration string

func (d *vaultDuration) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if bytes.Equal(b, []byte("null")) {
		*d = ""
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*d = vaultDuration(secondsIfBare(s))
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return errors.New("duration must be a string (e.g. \"1h\") or a number of seconds")
	}
	secs, err := n.Int64()
	if err != nil {
		return errors.New("duration in seconds must be a whole number")
	}
	*d = vaultDuration(strconv.FormatInt(secs, 10) + "s")
	return nil
}

// secondsIfBare turns a string of digits into a seconds duration ("3600" ->
// "3600s") and leaves anything else for time.ParseDuration to judge.
func secondsIfBare(s string) string {
	if s == "" {
		return s
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return s
		}
	}
	return s + "s"
}
