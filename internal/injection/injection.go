// Package injection flags prompt-injection text in responses, off the request path, never changing a response.
package injection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/Infisical/agent-vault/internal/auditchain"
)

// MaxBodyBytes bounds the response bytes handed to a screener.
const MaxBodyBytes = 256 << 10

// maxHitsPerBody bounds the rows one response can write.
const maxHitsPerBody = 8

// valueSep ends each decoded JSON string; it is not whitespace and is stripped from values, so no phrase spans two of them.
const valueSep = "\x00"

// dropLogEvery spaces the log lines that report unscreened responses.
const dropLogEvery = time.Minute

// Hit is one match: the rule that fired and the SHA-256 of the matched text, never the text.
type Hit struct {
	Rule string
	Sum  [sha256.Size]byte
}

// Screener finds injection text in a response body.
type Screener interface {
	Screen(body []byte) []Hit
}

type rule struct {
	name string
	re   *regexp.Regexp
}

// Heuristic is a local, model-free Screener: phrases that address the agent rather than describe the work.
type Heuristic struct{ rules []rule }

// NewHeuristic returns the built-in rule set.
func NewHeuristic() *Heuristic {
	def := func(name, expr string) rule { return rule{name, regexp.MustCompile(`(?i)` + expr)} }
	return &Heuristic{rules: []rule{
		def("override", `\b(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|system)\s+(instructions|prompts?|rules|messages)`),
		def("new_instructions", `\bnew\s+(instructions|system\s+prompt)\s*:`),
		def("role_reset", `\byou\s+are\s+now\s+(in\s+)?(a|an|the|developer|dan)\b`),
		def("reveal", `\b(reveal|print|show|output|send)\s+(me\s+)?(your\s+|the\s+)?(system\s+prompt|hidden\s+instructions|api\s+keys?|credentials|secrets|tokens?)\b`),
		def("concealment", `\bdo\s+not\s+(tell|inform|mention|reveal)\s+(this\s+to\s+)?the\s+user\b`),
		def("chat_markup", `<\|(im_start|im_end|system)\|>|\[/?INST\]|</?system>`),
		def("exfiltrate", `\b(exfiltrate|curl|wget)\b[^\n\x00]{0,80}https?://`),
	}}
}

// Screen returns each rule's first match in the decoded text of body.
func (h *Heuristic) Screen(body []byte) []Hit {
	text := plainText(body)
	var hits []Hit
	for _, r := range h.rules {
		if loc := r.re.FindIndex(text); loc != nil {
			hits = append(hits, Hit{Rule: r.name, Sum: sha256.Sum256(text[loc[0]:loc[1]])})
		}
	}
	return hits
}

// plainText undoes JSON string escapes and HTML entities, drops zero-width characters and maps Unicode spaces to a space so disguised phrases match.
func plainText(body []byte) []byte {
	var out strings.Builder
	dec := json.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := dec.Token()
		if err != nil {
			// A cut or non-JSON body: unescape what is left by hand.
			out.WriteString(strings.ReplaceAll(lenientUnescape(string(body[min(dec.InputOffset(), int64(len(body))):])), valueSep, ""))
			break
		}
		if str, ok := tok.(string); ok {
			out.WriteString(strings.ReplaceAll(str, valueSep, ""))
			out.WriteString(valueSep)
		}
	}
	// Unescape first so entity-encoded invisibles are stripped too.
	text := strings.Map(func(r rune) rune {
		switch {
		case r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\u2060' || r == '\ufeff' || r == '\u00ad':
			return -1
		case r != '\n' && unicode.IsSpace(r):
			return ' '
		}
		return r
	}, html.UnescapeString(out.String()))
	return []byte(text)
}

// lenientUnescape decodes JSON string escapes in text that may not be valid JSON.
func lenientUnescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n', 'r', 't':
			b.WriteByte('\n')
		case 'u':
			if i+4 < len(s) {
				if n, err := strconv.ParseUint(s[i+1:i+5], 16, 32); err == nil {
					b.WriteRune(rune(n))
					i += 4
					continue
				}
			}
			b.WriteByte('u')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// Item is one response body to screen, with the audit row it would write.
type Item struct {
	Event auditchain.Event // identity and request fields; Route says where the text came from
	Body  []byte
}

// Recorder writes audit rows.
type Recorder interface{ Record(auditchain.Event) error }

// Flagger screens items on background workers through a bounded queue; a full queue drops and counts the item.
type Flagger struct {
	screener Screener
	rec      Recorder
	queue    chan Item
	maxBytes int64
	held     atomic.Int64
	wg       sync.WaitGroup
	dropped  atomic.Uint64
	flagged  atomic.Uint64
	failed   atomic.Uint64
	once     sync.Once

	truncated atomic.Uint64
	capped    atomic.Uint64

	now      func() time.Time
	dropLog  rateLog
	truncLog rateLog
	capLog   rateLog
}

// rateLog spaces one log line per dropLogEvery and reports the count since the last line.
type rateLog struct {
	lastAt     atomic.Int64
	lastLogged atomic.Uint64
}

// New starts workers for up to queue pending items; maxBytes bounds the response bytes held at once.
func New(s Screener, rec Recorder, queue, workers int, maxBytes int64) *Flagger {
	f := &Flagger{screener: s, rec: rec, queue: make(chan Item, max(queue, 1)), maxBytes: max(maxBytes, 1), now: time.Now}
	for i := 0; i < max(workers, 1); i++ {
		f.wg.Add(1)
		go f.work()
	}
	return f
}

// Reserve claims n bytes of the budget, or counts a drop and reports false; Submit or Release frees them.
func (f *Flagger) Reserve(n int) bool {
	if f == nil {
		return false
	}
	if f.held.Add(int64(n)) > f.maxBytes {
		f.held.Add(-int64(n))
		f.noteDrop()
		return false
	}
	return true
}

// Release returns n reserved bytes that were never submitted.
func (f *Flagger) Release(n int) {
	if f != nil {
		f.held.Add(-int64(n))
	}
}

// Submit queues an item whose Body was reserved, without blocking, and reports whether it was queued.
func (f *Flagger) Submit(it Item) bool {
	if f == nil {
		return false
	}
	select {
	case f.queue <- it:
		return true
	default:
		f.noteDrop()
		f.Release(len(it.Body))
		return false
	}
}

// noteDrop counts a skipped screening and logs the running count at most once per dropLogEvery.
func (f *Flagger) noteDrop() {
	f.log(&f.dropLog, "injection: responses delivered unscreened", f.dropped.Add(1))
}

// NoteTruncated counts a response whose bytes past MaxBodyBytes were not screened.
func (f *Flagger) NoteTruncated() {
	if f != nil {
		f.log(&f.truncLog, "injection: responses screened only in part", f.truncated.Add(1))
	}
}

func (f *Flagger) log(l *rateLog, msg string, total uint64) {
	now := f.now().UnixNano()
	last := l.lastAt.Load()
	if now-last < int64(dropLogEvery) || !l.lastAt.CompareAndSwap(last, now) {
		return
	}
	slog.Warn(msg, slog.Uint64("since_last_log", total-l.lastLogged.Swap(total)), slog.Uint64("total", total))
}

// Dropped counts responses not screened because the queue or the byte budget was full.
func (f *Flagger) Dropped() uint64 { return f.dropped.Load() }

// Truncated counts responses longer than MaxBodyBytes, whose tail was not screened.
func (f *Flagger) Truncated() uint64 { return f.truncated.Load() }

// Capped counts responses whose hits beyond maxHitsPerBody were not recorded.
func (f *Flagger) Capped() uint64 { return f.capped.Load() }

// Flagged counts audit rows written.
func (f *Flagger) Flagged() uint64 { return f.flagged.Load() }

// Failed counts rows the audit trail refused.
func (f *Flagger) Failed() uint64 { return f.failed.Load() }

// Close stops accepting work after the queue drains.
func (f *Flagger) Close() {
	if f == nil {
		return
	}
	f.once.Do(func() { close(f.queue) })
	f.wg.Wait()
}

func (f *Flagger) work() {
	defer f.wg.Done()
	for it := range f.queue {
		hits := f.screener.Screen(it.Body)
		if len(hits) > maxHitsPerBody {
			f.log(&f.capLog, "injection: responses with hits over the per-response cap", f.capped.Add(1))
			hits = hits[:maxHitsPerBody]
		}
		for _, h := range hits {
			row := it.Event
			row.Event, row.Outcome, row.Decision, row.Match = auditchain.EventInjection, "flagged", h.Rule, hex.EncodeToString(h.Sum[:])
			row.Status, row.Duration = 0, 0
			if f.rec.Record(row) != nil {
				f.failed.Add(1)
				continue
			}
			f.flagged.Add(1)
		}
		f.Release(len(it.Body))
	}
}
