package main

import (
	"log/slog"
	"slices"
	"strings"
)

func shouldHandleSecret(secret string) bool {
	if d := strings.Split(secret, "/"); len(d) > 1 {
		if secretKey != "" && secret != secretKey {
			return false
		}
		if slices.Contains(excludes, d[0]) {
			slog.Debug("excluded", "key", secret)
			return false
		}
		if len(includes) > 0 && !slices.Contains(includes, d[0]) {
			slog.Debug("not in includes", "key", secret)
			return false
		}
	}

	return true
}
