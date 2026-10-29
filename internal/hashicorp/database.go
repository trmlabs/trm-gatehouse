package hashicorp

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	vaultapi "github.com/hashicorp/vault/api"
)

// DatabaseCredential is a dynamic database login minted by Vault's database
// secrets engine (GET <mount>/creds/<role>). Each read returns a distinct,
// short-lived Username/Password bound to its own LeaseID. The credential is
// SECRET: never log the password. The broker may log LeaseID as an audit join key.
type DatabaseCredential struct {
	LeaseID       string
	Username      string
	Password      string
	LeaseDuration time.Duration
	Renewable     bool
}

// ExpiresAt returns the credential's wall-clock expiry given when it was issued.
// The database engine returns a relative TTL, not an absolute time, so the
// caller anchors it conservatively to the start of the read request.
func (d DatabaseCredential) ExpiresAt(issuedAt time.Time) time.Time {
	return issuedAt.Add(d.LeaseDuration)
}

var databasePathSegment = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]*$`)

// ValidateDatabaseReference prevents path traversal and URL metacharacters from
// turning a database-role lookup into a different Vault API operation.
func ValidateDatabaseReference(mount, role string) error {
	mount = strings.Trim(strings.TrimSpace(mount), "/")
	role = strings.TrimSpace(role)
	if !databasePathSegment.MatchString(role) {
		return fmt.Errorf("invalid Vault database role")
	}
	for _, segment := range strings.Split(mount, "/") {
		if !databasePathSegment.MatchString(segment) {
			return fmt.Errorf("invalid Vault database mount")
		}
	}
	return nil
}

// ReadDatabaseCredential mints a fresh dynamic credential for a database role.
// mount is the database secrets-engine mount (e.g. "database"); role is a Vault
// role that maps to a set of SQL privileges. Every call yields a distinct
// username/password on its own lease, so one agent connection never reuses
// another's credential. The call is context-aware; cancellation propagates.
func (c *Client) ReadDatabaseCredential(ctx context.Context, mount, role string) (*DatabaseCredential, error) {
	mount = strings.Trim(strings.TrimSpace(mount), "/")
	role = strings.TrimSpace(role)
	if err := ValidateDatabaseReference(mount, role); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("%s/creds/%s", mount, role)
	// GET on this endpoint creates a role. Retrying an ambiguous response can
	// create extra credentials whose lease IDs we never receive. Clone per call
	// so concurrent KV reads retain their retry policy and token rotation is seen.
	mintAPI, err := c.api.CloneWithHeaders()
	if err != nil {
		return nil, fmt.Errorf("prepare credential request: %w", err)
	}
	mintAPI.SetToken(c.api.Token())
	mintAPI.SetMaxRetries(0)
	secret, err := mintAPI.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, credentialReadFailure(err)
	}
	if secret == nil {
		// The client returns no secret and no error only for a 404 without data.
		return nil, &CredentialReadError{Status: http.StatusNotFound,
			Detail: fmt.Sprintf("no credential at %s (is the database role configured?)", path)}
	}
	c.noteLease(secret.LeaseID)
	username := stringValue(secret.Data["username"])
	password := stringValue(secret.Data["password"])
	if username == "" || password == "" || secret.LeaseID == "" || secret.LeaseDuration <= 0 || int64(secret.LeaseDuration) > math.MaxInt64/int64(time.Second) {
		// Even an unusable response can represent a live minted role.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Second)
		defer cancel()
		if err := c.RevokeLease(cleanupCtx, secret.LeaseID); err != nil {
			return nil, fmt.Errorf("invalid database credential; cleanup failed")
		}
		return nil, fmt.Errorf("credential at %s is missing username or password, lease ID, or a positive TTL", path)
	}
	return &DatabaseCredential{
		LeaseID:       secret.LeaseID,
		Username:      username,
		Password:      password,
		LeaseDuration: time.Duration(secret.LeaseDuration) * time.Second,
		Renewable:     secret.Renewable,
	}, nil
}

// ErrCredentialNotIssued marks a credential read that Vault refused before any
// database user existed. Vault registers a lease only for a secret its database
// engine returned, and every failure after registration (audit, response
// handling) answers 5xx. So a 400, 403 or 404 is Vault's own evidence that the
// request created no user and no lease, while a 5xx, a timeout or a lost
// connection proves nothing either way.
var ErrCredentialNotIssued = errors.New("vault issued no database credential")

// CredentialReadError is a failed credential read as an operator's log shows
// it: Vault's HTTP status and its own error messages, or only the failure
// class when Vault did not answer. Vault never returned a credential, so none
// can be in it, and vaultMessages masks what a database error or a proxy could
// echo: a statement's literals, a connection string's password, a token.
type CredentialReadError struct {
	Status int    // Vault's HTTP status; 0 when Vault did not answer
	Detail string // Vault's messages, or the failure class
}

func (e *CredentialReadError) Error() string {
	if e.Status == 0 {
		return "database credential read failed: no answer from Vault (" + e.Detail + ")"
	}
	return fmt.Sprintf("database credential read failed: Vault answered %d: %s", e.Status, e.Detail)
}

func (e *CredentialReadError) Is(target error) bool {
	return target == ErrCredentialNotIssued &&
		(e.Status == http.StatusBadRequest || e.Status == http.StatusForbidden || e.Status == http.StatusNotFound)
}

func credentialReadFailure(err error) *CredentialReadError {
	var answered *vaultapi.ResponseError
	switch {
	case errors.As(err, &answered) && answered.RawError:
		// The body is not Vault's error JSON, so something in between answered
		// (a proxy or load balancer page), and such a body can echo the
		// request's headers, the Vault token among them. Only its size is told.
		size := 0
		for _, body := range answered.Errors {
			size += len(body)
		}
		return &CredentialReadError{Status: answered.StatusCode, Detail: fmt.Sprintf("a reply that is not Vault's error JSON (%d bytes)", size)}
	case errors.As(err, &answered):
		return &CredentialReadError{Status: answered.StatusCode, Detail: vaultMessages(answered.Errors)}
	case errors.Is(err, context.DeadlineExceeded):
		return &CredentialReadError{Detail: "timeout"}
	case errors.Is(err, context.Canceled):
		return &CredentialReadError{Detail: "canceled"}
	default:
		return &CredentialReadError{Detail: "network"}
	}
}

var (
	quotedLiteral = regexp.MustCompile(`'[^']*'`)
	nearToken     = regexp.MustCompile(`(?i)(at or near )"[^"]*"`)
	urlUserinfo   = regexp.MustCompile(`://[^/@\s]*@`)
	secretKey     = regexp.MustCompile(`(?i)password\w*|\bpwd\b|identified\s+by`)
	dollarTag     = regexp.MustCompile(`^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$`)
	vaultToken    = regexp.MustCompile(`\b(hv[sbr]\.)[A-Za-z0-9_-]+|\b([sbr]\.)[A-Za-z0-9]{24}\b`)
	bearerToken   = regexp.MustCompile(`(?i)\b(bearer\s+)[^\s"',;)}\]]+`)
)

// vaultMessages renders at most four of Vault's error messages, each on one
// line and cut to 300 characters. String literals, the token a syntax error
// points at, URL user info, the value after a password key or IDENTIFIED BY,
// Vault tokens and bearer tokens are masked, so a database error that echoes
// a CREATE ROLE statement, a connection string or a request cannot carry a
// password or a token.
func vaultMessages(messages []string) string {
	const maxMessages, maxLen = 4, 300
	var out []string
	for _, message := range messages {
		if len(out) == maxMessages {
			out = append(out, fmt.Sprintf("and %d more", len(messages)-maxMessages))
			break
		}
		message = strings.Join(strings.Fields(message), " ")
		message = maskSecretValues(message)
		message = quotedLiteral.ReplaceAllString(message, "'***'")
		message = nearToken.ReplaceAllString(message, `${1}"***"`)
		message = urlUserinfo.ReplaceAllString(message, "://***@")
		message = vaultToken.ReplaceAllString(message, "${1}${2}***")
		message = bearerToken.ReplaceAllString(message, "${1}***")
		if utf8.RuneCountInString(message) > maxLen {
			message = string([]rune(message)[:maxLen]) + "..."
		}
		if message != "" {
			out = append(out, message)
		}
	}
	if len(out) == 0 {
		return "no message"
	}
	return strings.Join(out, "; ")
}

// maskSecretValues masks the value after each password key (password,
// password_hash, PWD) and after IDENTIFIED BY. A quoted value, in JSON
// ("password":"x", or escaped inside another string as \"password\":\"x\"),
// SQL ('x' or "x") or dollar quoting ($$x$$ or $tag$x$tag$), is masked to its
// closing quote, or to the end of the message when it has none. After = or :
// a bare value is masked up to the next space or delimiter. A key followed by
// neither keeps the words after it, so "password authentication failed for
// user" still reads.
func maskSecretValues(message string) string {
	var out strings.Builder
	for {
		loc := secretKey.FindStringIndex(message)
		if loc == nil {
			out.WriteString(message)
			return out.String()
		}
		i := loc[1]
		for _, quote := range []string{`\"`, `"`} { // a JSON key's closing quote
			if strings.HasPrefix(message[i:], quote) {
				i += len(quote)
				break
			}
		}
		for i < len(message) && message[i] == ' ' {
			i++
		}
		assigned := i < len(message) && (message[i] == '=' || message[i] == ':')
		if assigned {
			for i++; i < len(message) && message[i] == ' '; i++ {
			}
		}
		open, end, closing := quotedValue(message[i:])
		if open == 0 && assigned {
			end = strings.IndexAny(message[i:], " ,;)}]\"'")
			if end < 0 {
				end = len(message) - i
			}
		}
		if end == 0 {
			out.WriteString(message[:loc[1]])
			message = message[loc[1]:]
			continue
		}
		out.WriteString(message[:i+open])
		out.WriteString("***")
		out.WriteString(message[i+end : i+end+closing])
		message = message[i+end+closing:]
	}
}

// quotedValue reports the quoted string s starts with: the length of its
// opening quote (0 when s starts with none), where its content ends, and the
// length of its closing quote (0 when it runs to the end of s). Inside a
// string escaped within another (\"x\"), a quote after three backslashes is
// part of the value, not its end.
func quotedValue(s string) (open, end, closing int) {
	switch {
	case strings.HasPrefix(s, `\"`):
		for k := 2; k < len(s); k++ {
			if s[k] == '"' && s[k-1] == '\\' && (k < 3 || s[k-2] != '\\') {
				return 2, k - 1, 2
			}
		}
		return 2, len(s), 0
	case strings.HasPrefix(s, `"`):
		for k := 1; k < len(s); k++ {
			switch s[k] {
			case '\\':
				k++
			case '"':
				return 1, k, 1
			}
		}
		return 1, len(s), 0
	case strings.HasPrefix(s, `'`):
		for k := 1; k < len(s); k++ {
			if s[k] != '\'' {
				continue
			}
			if k+1 < len(s) && s[k+1] == '\'' { // SQL's doubled quote
				k++
				continue
			}
			return 1, k, 1
		}
		return 1, len(s), 0
	}
	if tag := dollarTag.FindString(s); tag != "" {
		if k := strings.Index(s[len(tag):], tag); k >= 0 {
			return len(tag), len(tag) + k, len(tag)
		}
		return len(tag), len(s), 0
	}
	return 0, 0, 0
}

// RenewLease extends a lease by increment (a hint Vault may clamp to the role's
// max TTL) and returns the granted duration. Renewal keeps the same
// username/password valid, so a database session that outlives its original TTL
// is not interrupted. A non-renewable or already-expired lease returns an error.
func (c *Client) RenewLease(ctx context.Context, leaseID string, increment time.Duration) (time.Duration, error) {
	if leaseID == "" {
		return 0, fmt.Errorf("lease_id is required")
	}
	secret, err := c.api.Logical().WriteWithContext(ctx, "sys/leases/renew", map[string]interface{}{
		"lease_id":  leaseID,
		"increment": int(math.Ceil(increment.Seconds())),
	})
	if err != nil {
		return 0, fmt.Errorf("renew database lease failed")
	}
	if secret == nil || secret.LeaseDuration <= 0 || int64(secret.LeaseDuration) > math.MaxInt64/int64(time.Second) {
		return 0, fmt.Errorf("renew lease: missing positive TTL")
	}
	return time.Duration(secret.LeaseDuration) * time.Second, nil
}

// RevokeLease revokes a lease, immediately invalidating its credential: the
// database engine drops the generated user. This is the kill switch: a
// disconnected or compromised session's credential stops working at once rather
// than lingering until its TTL. An empty leaseID is a no-op (nothing was
// minted). A revoke that Vault rejects returns an error; callers on the
// shutdown/cleanup path must retain failed cleanup for retry. Production's
// durable minter also confirms lease absence before clearing its journal.
//
// The lease ID goes in the path, as RevokeDatabaseLeaseConfirmed does, so the
// broker's policy can grant revoke only under its own credential paths.
func (c *Client) RevokeLease(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil
	}
	for _, part := range strings.Split(leaseID, "/") {
		if !databasePathSegment.MatchString(part) {
			return fmt.Errorf("invalid database lease ID")
		}
	}
	if err := c.allowLeaseRevoke(leaseID); err != nil {
		return err
	}
	if _, err := c.api.Logical().WriteWithContext(ctx, "sys/leases/revoke/"+leaseID, map[string]interface{}{"sync": true}); err != nil {
		return fmt.Errorf("revoke database lease failed")
	}
	c.forgetLease(leaseID)
	return nil
}
