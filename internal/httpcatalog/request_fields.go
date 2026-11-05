package httpcatalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// RequestField limits one request parameter of a header entry to listed values; it must appear exactly once, in the query or a JSON or form body. A Slack entry must limit "channel", so a worker reaches only the listed channels, never a person or group conversation.
type RequestField struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

var (
	requestFieldName  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	requestFieldValue = regexp.MustCompile(`^[A-Za-z0-9_.:@/+-]{1,200}$`)
	// slackChannel admits only IDs starting with C, keeping out D (direct message), G (group) and U or W (a person); the prefix is Slack's convention, not a guarantee.
	slackChannel = regexp.MustCompile(`^C[A-Z0-9]{8,20}$`)
)

// slackMethods are the only Slack Web API paths an entry may list, each checked to name its one conversation in channel; any other method is refused until checked. Some name a person or second conversation in another parameter (files.completeUploadExternal channel_id, conversations.invite users, chat.postEphemeral user), which the channel rule would not see.
var slackMethods = map[string][]string{
	"/api/chat.postMessage": {"channel", "as_user", "attachments", "blocks", "current_draft_last_updated_ts", "icon_emoji", "icon_url",
		"link_names", "markdown_text", "metadata", "mrkdwn", "parse", "reply_broadcast", "text", "thread_ts", "unfurl_app_links",
		"unfurl_links", "unfurl_media", "username"},
	"/api/chat.update": {"channel", "ts", "as_user", "attachments", "blocks", "file_ids", "link_names", "markdown_text", "metadata",
		"parse", "reply_broadcast", "text", "unfurled_attachments"},
	"/api/reactions.add":         {"channel", "name", "timestamp"},
	"/api/conversations.history": {"channel", "cursor", "include_all_metadata", "inclusive", "latest", "limit", "oldest"},
	"/api/conversations.replies": {"channel", "ts", "cursor", "include_all_metadata", "inclusive", "latest", "limit", "oldest"},
}

// Operation names a request for the audit row from a fixed vocabulary: the Slack Web API method a listed path names (such as "slack.conversations_history"), else "". Never the path itself.
func (e *Entry) Operation(path string) string {
	if e == nil || !slackHost(e.Host) {
		return ""
	}
	if _, ok := slackMethods[path]; !ok {
		return ""
	}
	var b strings.Builder
	b.WriteString("slack.")
	for _, r := range strings.TrimPrefix(path, "/api/") {
		switch {
		case r == '.':
			b.WriteByte('_')
		case unicode.IsUpper(r):
			b.WriteByte('_')
			b.WriteRune(unicode.ToLower(r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

var ErrRequestField = errors.New("request field not allowed")

func slackHost(host string) bool { return host == "slack.com" || strings.HasSuffix(host, ".slack.com") }

func (e *Entry) normalizeRequestFields() error {
	seen := map[string]bool{}
	for _, f := range e.RequestFields {
		if !requestFieldName.MatchString(f.Name) || seen[f.Name] {
			return fmt.Errorf("request field %q must be a distinct plain name", f.Name)
		}
		seen[f.Name] = true
		if len(f.Values) == 0 {
			return fmt.Errorf("request field %q lists no values", f.Name)
		}
		values := map[string]bool{}
		for _, v := range f.Values {
			if !requestFieldValue.MatchString(v) || values[v] {
				return fmt.Errorf("request field %q value %q must be distinct and plain", f.Name, v)
			}
			values[v] = true
			if slackHost(e.Host) && f.Name == "channel" && !slackChannel.MatchString(v) {
				return fmt.Errorf("slack channel %q must be a channel ID (C...), never a person, direct or group conversation", v)
			}
		}
	}
	if slackHost(e.Host) {
		if !seen["channel"] {
			return errors.New("a Slack entry must limit channel to listed channel IDs (requestFields)")
		}
		for _, p := range e.PathPrefixes {
			if _, ok := slackMethods[p]; !ok {
				return fmt.Errorf("slack path %q is not allowed; list only /api/chat.postMessage, /api/chat.update, /api/reactions.add, /api/conversations.history and /api/conversations.replies", p)
			}
		}
	}
	return nil
}

func (e *Entry) CheckRequestFields(path, rawQuery string, contentTypes []string, body []byte) error {
	if len(e.RequestFields) == 0 {
		return nil
	}
	if len(contentTypes) > 1 {
		return ErrRequestField
	}
	contentType := ""
	if len(contentTypes) == 1 {
		contentType = contentTypes[0]
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ErrRequestField
	}
	var form url.Values
	var object map[string]json.RawMessage
	if len(bytes.TrimSpace(body)) > 0 {
		media, _, err := mime.ParseMediaType(contentType)
		switch {
		case err != nil:
			return ErrRequestField
		case media == "application/json":
			if object, err = uniqueObject(body); err != nil {
				return ErrRequestField
			}
		case media == "application/x-www-form-urlencoded":
			if form, err = url.ParseQuery(string(body)); err != nil {
				return ErrRequestField
			}
		default:
			return ErrRequestField
		}
	}
	// A vendor's parser may read a key as another name (PHP drops leading spaces, cuts at NUL, folds channel[] into channel), so a Slack request may use only its method's parameters and any request only plain keys.
	slack := slackHost(e.Host)
	allowed := slackMethods[path] // none for a path that is not exactly a listed method
	refused := func(key string) bool {
		return (slack && !contains(allowed, key)) || strings.ContainsFunc(key, foldedRune)
	}
	for _, values := range []url.Values{query, form} {
		for key := range values {
			if refused(key) {
				return ErrRequestField
			}
		}
	}
	for key := range object {
		if refused(key) {
			return ErrRequestField
		}
	}
	for _, f := range e.RequestFields {
		var found []string
		found = append(found, query[f.Name]...)
		found = append(found, form[f.Name]...)
		if raw, ok := object[f.Name]; ok {
			var s string
			if json.Unmarshal(raw, &s) != nil {
				return ErrRequestField
			}
			found = append(found, s)
		}
		if len(found) != 1 || !contains(f.Values, found[0]) {
			return ErrRequestField
		}
	}
	return nil
}

func foldedRune(r rune) bool {
	return unicode.IsSpace(r) || unicode.IsControl(r) || r == '[' || r == ']'
}

// uniqueObject decodes a JSON object with distinct top-level keys, since a vendor and the broker could read a repeated key differently.
func uniqueObject(body []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("bad key")
		}
		if _, dup := out[key]; dup {
			return nil, errors.New("duplicate key")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out[key] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errors.New("not an object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return out, nil
}
