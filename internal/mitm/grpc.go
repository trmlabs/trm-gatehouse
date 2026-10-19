package mitm

import (
	"context"
	"encoding/binary"
	"net/http"
	"strconv"
	"strings"
)

// HTTP/2 and gRPC on the catalog adapter's tunnels.
//
// A tunnel offers h2 only to a host whose catalog entries set http2 (see
// handleConnect); every other host keeps HTTP/1.1 exactly as before. A
// request that arrived over HTTP/2 is forwarded over HTTP/2 on connections
// the broker reuses, and its response trailers are screened and relayed. A
// gRPC call is a POST whose messages are length-prefixed frames in the body
// and whose status comes back in trailers.

// DefaultHTTP2MaxStreams bounds the concurrent requests on one worker's
// HTTP/2 tunnel. Each costs a goroutine and its buffers, as an HTTP/1.1
// tunnel does; a client that wants more opens another tunnel.
// AGENT_VAULT_MITM_HTTP2_MAX_STREAMS overrides it.
const DefaultHTTP2MaxStreams = 1000

type http2Key struct{}

// withHTTP2 marks a request that reached the broker over HTTP/2, so its
// upstream request goes over HTTP/2 too.
func withHTTP2(ctx context.Context) context.Context {
	return context.WithValue(ctx, http2Key{}, true)
}

func viaHTTP2(ctx context.Context) bool {
	h2, _ := ctx.Value(http2Key{}).(bool)
	return h2
}

// isGRPC reports whether r is a gRPC call: HTTP/2 with a gRPC content type
// (application/grpc, +proto, +json and the like; not gRPC-Web).
func isGRPC(r *http.Request) bool {
	if r.ProtoMajor != 2 {
		return false
	}
	ct := r.Header.Get("Content-Type")
	return ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+") || strings.HasPrefix(ct, "application/grpc;")
}

// grpcCompressedRequest reports a gRPC call whose messages the client
// compressed. The broker could not check them for decoys or placeholders,
// so the call is refused.
func grpcCompressedRequest(r *http.Request) bool {
	enc := r.Header.Get("Grpc-Encoding")
	return enc != "" && enc != "identity"
}

// prepareGRPC sets the gRPC protocol headers the broker owns on an upstream
// call: te, which gRPC servers use to detect a proxy that drops trailers, and
// an uncompressed response, so every byte that returns is screened.
func prepareGRPC(out *http.Request) {
	out.Header.Set("Te", "trailers")
	out.Header.Set("Grpc-Accept-Encoding", "identity")
}

// gRPC status codes (google.golang.org/grpc/codes).
const (
	grpcOK                 = 0
	grpcUnknown            = 2
	grpcInvalidArgument    = 3
	grpcPermissionDenied   = 7
	grpcResourceExhausted  = 8
	grpcFailedPrecondition = 9
	grpcInternal           = 13
	grpcUnimplemented      = 12
	grpcUnavailable        = 14
	grpcUnauthenticated    = 16
)

// grpcStatusFor maps the HTTP status of a broker refusal, or of an upstream
// answer that was not gRPC, to the gRPC status a client acts on. A passing
// refusal (it carries Retry-After) is UNAVAILABLE, which gRPC clients retry,
// and a lasting 503 is FAILED_PRECONDITION, which they do not.
func grpcStatusFor(status int, passing bool) int {
	switch status {
	case http.StatusBadRequest:
		return grpcInvalidArgument
	case http.StatusUnauthorized, http.StatusProxyAuthRequired:
		return grpcUnauthenticated
	case http.StatusForbidden, http.StatusMethodNotAllowed:
		return grpcPermissionDenied
	case http.StatusNotFound:
		return grpcUnimplemented
	case http.StatusRequestEntityTooLarge:
		return grpcResourceExhausted
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusGatewayTimeout:
		return grpcUnavailable
	case http.StatusServiceUnavailable:
		if passing {
			return grpcUnavailable
		}
		return grpcFailedPrecondition
	}
	return grpcUnknown
}

// maxGRPCMessage bounds grpc-message: gRPC clients refuse response metadata
// past 8 KiB in all, and the broker's own text is one line.
const maxGRPCMessage = 1024

// grpcWriter answers a gRPC call the way gRPC clients read a failure when the
// broker refuses it, or the upstream answers with an HTTP error: status 200,
// no messages, and grpc-status and grpc-message trailers, with Retry-After
// also as grpc-retry-pushback-ms. The refusal code stays in RefusalHeader.
// Without it a client would report only "unexpected HTTP status". A 200
// passes through untouched; fail ends one that is already streaming.
type grpcWriter struct {
	http.ResponseWriter
	wroteHeader bool
	failed      bool
	message     []byte
}

func (g *grpcWriter) WriteHeader(status int) {
	if g.wroteHeader {
		return
	}
	g.wroteHeader = true
	if status == http.StatusOK {
		g.ResponseWriter.WriteHeader(status)
		return
	}
	h := g.Header()
	retryAfter := h.Get("Retry-After")
	refused := h.Get(RefusalHeader) != ""
	h.Del("Content-Length")
	h.Del("X-Content-Type-Options")
	h.Set("Content-Type", "application/grpc")
	g.failed = true
	g.ResponseWriter.WriteHeader(http.StatusOK)
	h.Set(http.TrailerPrefix+"Grpc-Status", strconv.Itoa(grpcStatusFor(status, retryAfter != "")))
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
		h.Set(http.TrailerPrefix+"Grpc-Retry-Pushback-Ms", strconv.Itoa(seconds*1000))
	}
	if !refused {
		// An upstream error page or a broker transport error: say which
		// status, never the body.
		h.Set(http.TrailerPrefix+"Grpc-Message", grpcMessage("HTTP "+strconv.Itoa(status)+" "+http.StatusText(status)))
	}
}

// Write passes a 200's body through. After a refusal it keeps the broker's
// one-line text as grpc-message, since a gRPC client never shows a body.
func (g *grpcWriter) Write(p []byte) (int, error) {
	if !g.wroteHeader {
		g.WriteHeader(http.StatusOK)
	}
	if !g.failed {
		return g.ResponseWriter.Write(p)
	}
	if g.Header().Get(RefusalHeader) != "" {
		if room := maxGRPCMessage - len(g.message); room > 0 {
			g.message = append(g.message, p[:min(room, len(p))]...)
		}
		g.Header().Set(http.TrailerPrefix+"Grpc-Message", grpcMessage("gatehouse refused: "+strings.TrimSpace(string(g.message))))
	}
	return len(p), nil
}

// fail ends a call whose response is already streaming with a gRPC status in
// its trailers, so the client discards what it has instead of reading a
// clean end.
func (g *grpcWriter) fail(code int, message string) {
	if !g.wroteHeader {
		g.WriteHeader(http.StatusOK)
	}
	g.Header().Set(http.TrailerPrefix+"Grpc-Status", strconv.Itoa(code))
	g.Header().Set(http.TrailerPrefix+"Grpc-Message", grpcMessage(message))
}

func (g *grpcWriter) Flush() {
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (g *grpcWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

// grpcMessage percent-encodes text for grpc-message, as the gRPC wire format
// requires for anything outside printable ASCII and for "%" itself.
func grpcMessage(text string) string {
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c < ' ' || c > '~' || c == '%' {
			b.WriteString("%" + strings.ToUpper(strconv.FormatInt(int64(c)|0x100, 16)[1:]))
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// grpcCallStatus is the grpc-status a gRPC response ended with, from its
// trailers or, for a response with no messages, its headers; -1 when it
// carries none.
func grpcCallStatus(resp *http.Response) int {
	v := resp.Trailer.Get("Grpc-Status")
	if v == "" {
		v = resp.Header.Get("Grpc-Status")
	}
	code, err := strconv.Atoi(v)
	if err != nil {
		return -1
	}
	return code
}

// grpcFrames follows a gRPC body's length-prefixed messages: a 5-byte header
// (a compression flag and a big-endian length), then the message.
type grpcFrames struct {
	header     [5]byte
	have       int    // header bytes read for the current message
	left       uint32 // message bytes still to come
	compressed bool   // a message set the compression flag
}

// advance consumes b and reports whether the bytes so far end exactly at a
// message boundary.
func (f *grpcFrames) advance(b []byte) bool {
	for len(b) > 0 {
		if f.have < len(f.header) {
			n := copy(f.header[f.have:], b)
			f.have += n
			b = b[n:]
			if f.have == len(f.header) {
				f.compressed = f.compressed || f.header[0] != 0
				f.left = binary.BigEndian.Uint32(f.header[1:])
				if f.left == 0 {
					f.have = 0
				}
			}
			continue
		}
		n := min(uint32(len(b)), f.left) // #nosec G115 -- len(b) is a read buffer's length
		f.left -= n
		b = b[n:]
		if f.left == 0 {
			f.have = 0
		}
	}
	return f.have == 0
}

// framesSafe reports whether no needle holds a byte a message header can
// start with. Then no needle can straddle a message boundary, since the next
// byte after one is a header's compression flag, 0 or 1.
func framesSafe(needles [][]byte) bool {
	for _, n := range needles {
		for _, c := range n {
			if c < ' ' {
				return false
			}
		}
	}
	return true
}

// upstreamFor is the transport for an upstream request: HTTP/2 only when the
// worker's request arrived over HTTP/2, which a gRPC server needs, else the
// HTTP/1.1 transport. The HTTP/2 one is built from the HTTP/1.1 one on first
// use, with its dialer, egress checks and TLS verification.
func (p *Proxy) upstreamFor(out *http.Request) http.RoundTripper {
	if !viaHTTP2(out.Context()) {
		return p.upstream
	}
	if t := p.h2Upstream.Load(); t != nil {
		return t
	}
	t := p.upstream.Clone()
	t.Protocols = new(http.Protocols)
	t.Protocols.SetHTTP2(true)
	// Calls share connections, as HTTP/2 intends. Strict mode turns off
	// HTTP/1.1 keep-alives so the transport never resends a request on a
	// reused connection that may have reached the server; HTTP/2 resends
	// only one the server refused unprocessed (GOAWAY past it, or
	// REFUSED_STREAM). Without HTTP/1.1 here, an upstream that does not
	// offer HTTP/2 fails the call rather than reusing HTTP/1.1 connections.
	t.DisableKeepAlives = false
	if p.h2Upstream.CompareAndSwap(nil, t) {
		return t
	}
	return p.h2Upstream.Load()
}

// grpcCompressedResponse reports a gRPC response that compresses its
// messages despite the broker asking for none: it could not be screened.
func grpcCompressedResponse(h http.Header) bool {
	enc := h.Get("Grpc-Encoding")
	return enc != "" && enc != "identity"
}

// grpcStreamStatus is the status that ends a gRPC call whose response the
// broker stopped relaying mid-stream.
func grpcStreamStatus(outcome string) int {
	switch outcome {
	case "response_too_large":
		return grpcResourceExhausted
	case "upstream_error":
		return grpcUnavailable
	}
	return grpcInternal
}
