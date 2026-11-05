//go:build e2e

package httpcatalog

// AllowPlaintextDatabases lets Kubernetes Service hosts use sslmode disable or plain http; it exists only in e2e-tag binaries.
func AllowPlaintextDatabases() { plaintextDatabases.Store(true) }

func init() { rolesWithoutEnvironment = true }
