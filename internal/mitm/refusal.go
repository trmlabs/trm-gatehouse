package mitm

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// RefusalHeader names, on every response the catalog adapter refuses, why it
// refused: a fixed code an agent can branch on without parsing prose. The
// body carries the same code and a one-line next step. A code is fixed text
// from the refusals table, never request data, and says no more about the
// catalog than the status already does. A request on an entry the caller's
// pool is not granted answers "unlisted" (403), except that the method check
// runs first: a method that entry does not list answers "method" (405). The
// audit row records the refusal and the status sent; its outcome can be more
// specific than the code ("pool" where the agent sees "unlisted", or an
// outcome with no table entry where the agent sees "refused") or less
// ("refused" for a check made before the request reached the catalog). The
// broker sets this header only on its own refusals and strips it from every
// upstream response, so its presence means the request was refused here.
const RefusalHeader = brokercore.RefusalHeader

// refusalKind is how one refusal code answers. A passing refusal (one the
// same request may clear by waiting) sets retryAfter and answers 503, or 429
// when the requester's own rate caused it; a lasting one keeps its 4xx, or
// answers 503 without Retry-After when only an operator can clear it.
type refusalKind struct {
	status     int    // the status this code always answers with; 0 keeps the caller's
	retryAfter int    // seconds; set only when retrying the same request can succeed
	closeConn  bool   // the retry can succeed only on a new connection
	next       string // one line telling the agent what to do
}

const (
	nextRetry      = "this is temporary; wait for Retry-After, then send the same request again; if the third retry is refused the same way, stop and report it."
	nextNotAllowed = "the catalog does not allow this request; do not retry it, report it or ask for a catalog change."
	nextFixRequest = "the broker does not forward a request of this form; change the request, do not resend it as is."
	nextSession    = "the runner session was refused; start a new session and do not reuse this one."
	nextReport     = "this needs an operator; report it and do not retry."
)

var refusals = map[string]refusalKind{
	// Passing: the same request can succeed once the condition clears. The
	// runner session is read once per tunnel, from its CONNECT, so
	// session_missing closes the connection for the retry to open a new one.
	"audit_unavailable":        {status: http.StatusServiceUnavailable, retryAfter: 5, next: "the audit trail is not recording; " + nextRetry},
	"broker_unavailable":       {status: http.StatusServiceUnavailable, retryAfter: 1, next: "this broker cannot take the request now; " + nextRetry},
	"key_unavailable":          {status: http.StatusServiceUnavailable, retryAfter: 5, next: "the destination key could not be read; " + nextRetry},
	"token_unavailable":        {status: http.StatusServiceUnavailable, retryAfter: 5, next: "a token for the destination could not be minted; " + nextRetry},
	"target_lookup":            {status: http.StatusServiceUnavailable, retryAfter: 5, next: "GitHub could not be asked what this GraphQL request's pull request or label is; " + nextRetry},
	"seed_unavailable":         {status: http.StatusServiceUnavailable, retryAfter: 5, next: "the browser session could not be prepared; " + nextRetry},
	"session_missing":          {status: http.StatusServiceUnavailable, retryAfter: 5, closeConn: true, next: "no runner session reached the broker with this connection; " + nextRetry},
	"entitlement_unavailable":  {status: http.StatusServiceUnavailable, retryAfter: 5, next: "the directory could not confirm your access; " + nextRetry},
	"entitlement_rate_limited": {status: http.StatusTooManyRequests, retryAfter: 60, next: "too many access checks for this person in the last minute; " + nextRetry},
	"busy":                     {status: http.StatusTooManyRequests, retryAfter: 5, next: "the broker is at its connection limit, or this address has too many failed sign-ins; " + nextRetry},
	// The limiter's own wait replaces this second when it gives one; when it
	// gives none, the second still keeps an agent from retrying at once.
	"rate_limited": {status: http.StatusTooManyRequests, retryAfter: 1, next: "this workload is over its request rate for the destination; " + nextRetry},

	// Lasting: the same request will be refused again.
	"broker_misconfigured":   {status: http.StatusServiceUnavailable, next: "the broker is not set up to serve this destination; " + nextReport},
	"key_deleted":            {status: http.StatusServiceUnavailable, next: "the destination key was deleted, emptied or revoked in Vault; " + nextReport},
	"key_not_header_safe":    {status: http.StatusServiceUnavailable, next: "the stored destination key cannot be sent in a header; " + nextReport},
	"seed_deadline":          {status: http.StatusServiceUnavailable, next: "this worker ends too soon for a browser session; start a new run."},
	"authentication":         {next: "the broker could not identify this workload; check the proxy credentials, then report it."},
	"identity":               {next: "the broker refused this workload's identity; " + nextReport},
	"plain_http":             {next: "send the request over HTTPS through the proxy."},
	"unlisted":               {next: "no catalog entry for this pool lists this host and path; " + nextNotAllowed},
	"method":                 {next: "the catalog does not list this method for this destination; " + nextNotAllowed},
	"request_shape":          {next: nextFixRequest},
	"request_too_large":      {next: "the request body is over this destination's limit; send a smaller one."},
	"placeholder_misplaced":  {next: "a placeholder may appear only in the destination's credential header; remove it from the URL, body and other headers."},
	"credential_header":      {next: "send the destination's credential header once, with the placeholder only, or leave it out."},
	"request_field":          {next: "a limited request field is missing, repeated or not one the catalog lists; " + nextNotAllowed},
	"push_shape":             {next: nextFixRequest},
	"read_only":              {next: "this repository is read-only for this pool; " + nextNotAllowed},
	"read_only_path":         {next: "this path is read-only for this pool; " + nextNotAllowed},
	"denied_path":            {next: nextNotAllowed},
	"ref_outside_binding":    {next: "this push names a branch outside the ones this pool may write; " + nextNotAllowed},
	"head":                   {next: "this pull request's branch is outside the ones this pool may write; " + nextNotAllowed},
	"comment_target":         {next: "GitHub did not confirm, or could not be asked, that this comment is one this pool's app wrote on a pull request it may change; report it."},
	"pull_request_target":    {next: "GitHub did not confirm, or could not be asked, that this pull request is one this pool may change; report it."},
	"run_target":             {next: "GitHub did not confirm, or could not be asked, that this workflow run is one this pool may rerun; report it."},
	"graphql_shape":          {next: "the broker could not read this GraphQL request as one JSON query with its variables; " + nextFixRequest},
	"graphql_unmapped":       {next: "the broker maps no operation to a field, mutation or directive in this GraphQL request, so no catalog change allows it; do not retry it, report it."},
	"graphql_limit":          {next: "this GraphQL request is over the broker's limits on size, depth, aliases, fields, page size or cost; send a smaller one."},
	"graphql_introspection":  {next: "the broker answers gh's own schema checks and forwards no other introspection; " + nextFixRequest},
	"graphql_repository":     {next: "a GraphQL request must reach exactly one repository, named by repository(owner, name), a repo: search qualifier or a node ID; send one per repository."},
	"pool_ceiling":           {next: "this destination's tier is above what this pool may reach; " + nextNotAllowed},
	"pool_external":          {next: "this pool may reach no catalog entry; " + nextNotAllowed},
	"no_identity":            {next: "this destination needs a pool that names who runs it; " + nextNotAllowed},
	"no_person":              {next: "this destination needs a person behind the run, and this run names none; run it as yourself."},
	"not_entitled":           {next: "your account lacks a group this destination requires; ask for access, do not retry."},
	"not_in_directory":       {next: "the directory has no account for this person; " + nextReport},
	"account_disabled":       {next: "the requester's account is disabled; " + nextReport},
	"workload_not_entitled":  {next: "this pool's workload is not entitled to this destination; " + nextNotAllowed},
	"entitlement_config":     {next: "this destination's access check is not configured; " + nextReport},
	"session_token":          {next: nextSession},
	"session_pool":           {next: nextSession},
	"session_run":            {next: nextSession},
	"session_pod_mismatch":   {next: nextSession},
	"session_pod_owner":      {next: "this Pod already serves another person's run; start a new run on its own Pod."},
	"session_unexpected":     {next: "a runner session arrived on a pool that takes none; " + nextReport},
	"session_unbindable":     {next: "the runner session could not be pinned to this Pod; " + nextReport},
	"session_unverifiable":   {next: "the broker cannot verify runner sessions for this pool; " + nextReport},
	"requester_unexpected":   {next: nextReport},
	"requester_missing":      {next: nextReport},
	"requester_unverifiable": {next: nextReport},
	"refused":                {next: "the broker refused this request; " + nextReport},
}

// refusalCode is the code an agent sees for an audit outcome: the outcome
// itself, except that "pool" is told apart from "unlisted" in the audit row
// only, and an outcome with no entry in refusals answers "refused". Only the
// table's fixed codes reach the agent, so an outcome a later change builds
// from an error or a reason stays in the audit row.
func refusalCode(outcome string) string {
	if outcome == "pool" {
		return "unlisted"
	}
	if _, ok := refusals[outcome]; !ok {
		return "refused"
	}
	return outcome
}

// identityRefusalCode is the code for a refusal made before the request
// reached the catalog, whose audit outcome is "refused": its status says
// which check refused it.
func identityRefusalCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "request_shape"
	case http.StatusProxyAuthRequired:
		return "authentication"
	case http.StatusTooManyRequests:
		return "busy"
	case http.StatusServiceUnavailable:
		return "broker_unavailable"
	}
	return "identity"
}

// refusalFor resolves a code and the status its caller chose into the code,
// status and kind to answer with. A code with no entry answers as "refused",
// whatever path it came by.
func refusalFor(code string, status int) (string, int, refusalKind) {
	kind, ok := refusals[code]
	if !ok {
		code, kind = "refused", refusals["refused"]
	}
	if kind.status != 0 {
		status = kind.status
	}
	return code, status, kind
}

// after is kind with a limiter's own wait as its Retry-After, rounded up to a
// whole second, when the limiter gave one.
func (k refusalKind) after(wait time.Duration) refusalKind {
	if wait > 0 {
		k.retryAfter = int(math.Ceil(wait.Seconds()))
	}
	return k
}

// writeRefusal answers a refused request: the code in RefusalHeader,
// Retry-After for a passing refusal, and a one-line body naming the code and
// the next step. A refusal that only a new connection can clear also closes
// this one.
func writeRefusal(w http.ResponseWriter, status int, code string, kind refusalKind) {
	w.Header().Set(RefusalHeader, code)
	if kind.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(kind.retryAfter))
	}
	if kind.closeConn {
		w.Header().Set("Connection", "close")
	}
	http.Error(w, code+": "+kind.next, status)
}

// refuseWith answers a refusal that has no row of its own to write, such as
// one made after the request was admitted, whose response row records it. A
// code with a fixed status answers with that status; any other keeps status.
func refuseWith(w http.ResponseWriter, status int, code string) {
	code, status, kind := refusalFor(code, status)
	writeRefusal(w, status, code, kind)
}

// refuse is refuseWith for a refusal that is 503 unless its code fixes
// another status.
func refuse(w http.ResponseWriter, code string) {
	refuseWith(w, http.StatusServiceUnavailable, code)
}

// keyOutcome names a key read failure: a key that is deleted, emptied or
// revoked in Vault, and one a header cannot carry, apart from one that could
// not be read, so the operator sees what to fix and the agent does not wait
// on a refusal that only an operator can clear.
func keyOutcome(err error) string {
	switch {
	case errors.Is(err, httpcatalog.ErrKeyNotHeaderSafe):
		return "key_not_header_safe"
	case errors.Is(err, httpcatalog.ErrKeyDeleted):
		return "key_deleted"
	}
	return "key_unavailable"
}

// seedOutcome names a browser seed failure: a worker whose deadline is too
// close, which only gets closer, apart from any other.
func seedOutcome(err error) string {
	if errors.Is(err, errSeedDeadline) {
		return "seed_deadline"
	}
	return "seed_unavailable"
}
