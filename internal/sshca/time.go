package sshca

import (
	"fmt"
	"math"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

func unixTimeSeconds(t time.Time) (uint64, error) {
	sec := t.Unix()
	if sec < 0 {
		return 0, fmt.Errorf("time %s is before Unix epoch", t.UTC().Format(time.RFC3339))
	}
	return strconv.ParseUint(strconv.FormatInt(sec, 10), 10, 64)
}

// FormatUnixTime returns an RFC3339 UTC timestamp for SSH certificate seconds.
func FormatUnixTime(sec uint64) string {
	if sec == ssh.CertTimeInfinity {
		return "forever"
	}
	if sec > uint64(math.MaxInt64) {
		return strconv.FormatUint(sec, 10)
	}

	parsed, err := strconv.ParseInt(strconv.FormatUint(sec, 10), 10, 64)
	if err != nil {
		return strconv.FormatUint(sec, 10)
	}
	return time.Unix(parsed, 0).UTC().Format(time.RFC3339)
}
