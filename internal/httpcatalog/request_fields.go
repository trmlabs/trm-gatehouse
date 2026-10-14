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
)

// RequestField limits one request parameter of a header entry to listed
// values. The parameter must appear exactly once in the whole request, in the
// query string or in a JSON object or form body, as a string equal to one of
// Values. A Slack entry must limit "channel", so a worker can post only to the
// listed channels and never to a person or a group conversation.
type RequestField struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

var (
	requestFieldName  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	requestFieldValue = regexp.MustCompile(`^[A-Za-z0-9_.:@/+-]{1,200}$`)
	// slackChannel admits only IDs starting with C, which keeps out D (direct
	// message), G (group conversation or legacy private channel), U and W (a
	// person, which Slack turns into a direct message). The prefix is Slack's
	// convention, not a guarantee of the conversation's type.
	slackChannel = regexp.MustCompile(`^C[A-Z0-9]{8,20}$`)
)

// slackMethods are the only Slack Web API paths an entry may list. Each takes
// one channel and posts or edits a message there. Other methods name a person
// or a second conversation in another parameter (files.completeUploadExternal
// channel_id, conversations.invite users, chat.postEphemeral user), which the
// channel rule would not see.
var slackMethods = map[string]bool{"/api/chat.postMessage": true, "/api/chat.update": true}

// ErrRequestField is a request whose limited parameters are missing,
// repeated, placed twice or not listed, or whose body cannot be read safely.
var ErrRequestField = errors.New("request field not allowed")

// slackHost reports whether host is Slack's Web API.
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
			if !slackMethods[p] {
				return fmt.Errorf("slack path %q is not allowed; list only /api/chat.postMessage and /api/chat.update", p)
			}
		}
	}
	return nil
}

// CheckRequestFields holds a request to the entry's RequestFields. rawQuery is
// the query string, contentTypes every Content-Type header value and body the
// whole request body. Every refusal is ErrRequestField.
func (e *Entry) CheckRequestFields(rawQuery string, contentTypes []string, body []byte) error {
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
	for _, f := range e.RequestFields {
		// Some parsers fold channel[] or channel[0] into channel; a key like
		// that beside the limited one could name a second conversation.
		for _, values := range []url.Values{query, form} {
			for key := range values {
				if key != f.Name && strings.HasPrefix(key, f.Name+"[") {
					return ErrRequestField
				}
			}
		}
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

// uniqueObject decodes a JSON object whose top-level keys are all distinct;
// a vendor and the broker could read a repeated key differently.
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
	// Only whitespace may follow: a second value and bytes the decoder
	// rejects (x, ], a comma, NUL) are both trailing data.
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return out, nil
}
