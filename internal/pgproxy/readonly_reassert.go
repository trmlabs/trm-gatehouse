package pgproxy

import (
	"encoding/binary"
	"io"
	"sync"
)

// reassertSQL turns the read-only default back on before each transaction.
const reassertSQL = "SET default_transaction_read_only = on"

// reassertFilter counts the ReadyForQuery messages the database owes and drops
// the answer to reassertSQL, so the client never sees it.
type reassertFilter struct {
	w io.Writer

	mu     sync.Mutex
	cond   *sync.Cond
	owed   int  // ReadyForQuery messages still to come for what was forwarded
	open   bool // an extended-protocol batch is open: no Sync forwarded yet
	status byte // transaction status of the last ReadyForQuery
	dirty  bool // the client sent something since the last reassertSQL
	closed bool
	failed bool // the database answered reassertSQL with an error

	swallow bool // the next messages answer reassertSQL, through its ReadyForQuery
	header  [5]byte
	have    int
	left    int64
	typ     byte
	drop    bool
	first   bool
}

func newReassertFilter(w io.Writer) *reassertFilter {
	f := &reassertFilter{w: w, status: 'I', dirty: true}
	f.cond = sync.NewCond(&f.mu)
	return f
}

// close wakes a client side waiting for an answer the database will not send.
func (f *reassertFilter) close() {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	f.cond.Broadcast()
}

func (f *reassertFilter) Write(p []byte) (int, error) {
	total := len(p)
	f.mu.Lock()
	defer f.mu.Unlock()
	for len(p) > 0 {
		if f.left == 0 && f.have < len(f.header) {
			k := copy(f.header[f.have:], p)
			f.have += k
			p = p[k:]
			if f.have < len(f.header) {
				break
			}
			length := int64(binary.BigEndian.Uint32(f.header[1:]))
			if length < 4 {
				return total - len(p), io.ErrUnexpectedEOF
			}
			f.typ, f.left, f.first, f.drop = f.header[0], length-4, true, f.swallow
			f.have = 0
			if f.drop && f.typ == 'E' {
				f.failed = true
			}
			if !f.drop {
				if _, err := f.w.Write(f.header[:]); err != nil {
					return total - len(p), err
				}
			}
			f.finish()
			continue
		}
		k := int64(len(p))
		if k > f.left {
			k = f.left
		}
		if f.first && f.typ == 'Z' {
			f.status = p[0]
		}
		f.first = false
		if !f.drop {
			if _, err := f.w.Write(p[:k]); err != nil {
				return total - len(p), err
			}
		}
		f.left -= k
		p = p[k:]
		f.finish()
	}
	return total, nil
}

// finish counts a message once it is whole.
func (f *reassertFilter) finish() {
	if f.left != 0 || f.typ != 'Z' {
		return
	}
	if f.owed > 0 {
		f.owed--
	}
	if f.drop {
		f.swallow = false
	}
	f.typ = 0
	f.cond.Broadcast()
}

// beforeMessage waits until a transaction is about to start and reports whether
// reassertSQL must go first; ok is false when the session ended meanwhile.
func (f *reassertFilter) beforeMessage(kind byte, flush func() error) (send, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if kind == 'X' {
		return false, true
	}
	if f.open || !f.dirty {
		return false, !f.failed
	}
	if f.owed > 0 {
		f.mu.Unlock()
		err := flush()
		f.mu.Lock()
		if err != nil {
			return false, false
		}
		for f.owed > 0 && !f.closed {
			f.cond.Wait()
		}
	}
	if f.closed || f.failed {
		return false, false
	}
	return f.status == 'I', true
}

// sent records that reassertSQL was forwarded: its answer is dropped.
func (f *reassertFilter) sent() {
	f.mu.Lock()
	f.owed++
	f.swallow, f.dirty = true, false
	f.mu.Unlock()
}

// forwarded records a client message that went upstream.
func (f *reassertFilter) forwarded(kind byte) {
	f.mu.Lock()
	f.dirty = true
	switch kind {
	case 'Q':
		f.owed++
		f.open = false
	case 'S':
		f.owed++
		f.open = false
	default:
		f.open = true
	}
	f.mu.Unlock()
}
