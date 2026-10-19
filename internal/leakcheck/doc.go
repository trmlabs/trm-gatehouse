// Package leakcheck holds a test that keeps operator-internal names out of
// this public repository: internal hostnames, staging domains, identity
// tenant IDs, cloud project and service account names. Examples, docs and
// tests use example.com style placeholders instead. The list of names is the
// operator's and is read from LEAKCHECK_DENIED_TOKENS, which CI sets from a
// repository secret; without it the test checks only the patterns it holds.
package leakcheck
