package brokercore

import (
	"errors"
	"os"
	"regexp"
)

var replicaPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

// ReplicaName is AGENT_VAULT_REPLICA, then AGENT_VAULT_AUDIT_REPLICA, then the hostname.
func ReplicaName(getenv func(string) string) string {
	for _, key := range []string{"AGENT_VAULT_REPLICA", "AGENT_VAULT_AUDIT_REPLICA"} {
		if v := getenv(key); v != "" {
			return v
		}
	}
	host, _ := os.Hostname()
	return host
}

// ErrFleetReplicaName means brokers share a store but this one has no AGENT_VAULT_REPLICA; a shared fallback name would share an audit chain.
var ErrFleetReplicaName = errors.New("AGENT_VAULT_REPLICA (the Pod name, from the downward API) is required when brokers share a store (DATABASE_URL or DATABASE_URL_FILE)")

// FleetReplicaName is ReplicaName, but brokers sharing a store (DATABASE_URL or DATABASE_URL_FILE) must set AGENT_VAULT_REPLICA.
func FleetReplicaName(getenv func(string) string) (string, error) {
	if getenv("DATABASE_URL") == "" && getenv("DATABASE_URL_FILE") == "" {
		return ReplicaName(getenv), nil
	}
	if v := getenv("AGENT_VAULT_REPLICA"); v != "" {
		return v, nil
	}
	return "", ErrFleetReplicaName
}

// ValidReplicaName reports whether a name is a DNS-style replica name.
func ValidReplicaName(name string) bool { return replicaPattern.MatchString(name) }
