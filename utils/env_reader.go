package utils

import (
	"os"
	"strings"
)

// iptLBEnv for reading IPTLB env into a map
type iptLBEnv map[string]string

// IPTLBPrefix Prefix for reading the env
var IPTLBPrefix string = "IPTLB_"

// GetIPTLBEnv will read environ and create a map of k:v from envs
// that have a IPTLB_ prefix. The prefix is removed
func GetIPTLBEnv(p string) map[string]string {
	var key string
	env := make(iptLBEnv)
	osEnviron := os.Environ()
	iptLBPRefix := p
	for _, b := range osEnviron {
		if strings.HasPrefix(b, iptLBPRefix) {
			pair := strings.SplitN(b, "=", 2)
			key = strings.TrimPrefix(pair[0], iptLBPRefix)
			key = strings.ToLower(key)
			key = strings.Replace(key, "_", ".", -1)
			env[key] = pair[1]
		}
	}

	return env
}
