package mitm

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// HTTP/2 and gRPC on the catalog adapter: a tunnel offers h2 only to a host whose catalog entries set http2 (see handleConnect).
// A request that arrived over HTTP/2 is forwarded over HTTP/2 and its response trailers are screened.

// DefaultHTTP2MaxStreams bounds concurrent requests on one worker's HTTP/2 tunnel; AGENT_VAULT_MITM_HTTP2_MAX_STREAMS overrides it.
const DefaultHTTP2MaxStreams = 1000

type http2Key struct{}

func withHTTP2(ctx context.Context) context.Context {
	return context.WithValue(ctx, http2Key{}, true)
}

func viaHTTP2(ctx context.Context) bool {
	h2, _ := ctx.Value(http2Key{}).(bool)
	return h2
}

// isGRPC reports whether r is a gRPC call: HTTP/2 with a gRPC content type (not gRPC-Web).
func isGRPC(r *http.Request) bool {
	if r.ProtoMajor != 2 {
		return false
	}
	ct := r.Header.Get("Content-Type")
	return ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+") || strings.HasPrefix(ct, "application/grpc;")
}

// grpcCompressedRequest reports a gRPC call compressed with anything but gzip, which the broker cannot check for decoys or placeholders and so refuses; gzip is handled by grpcPlainMessages.
func grpcCompressedRequest(r *http.Request) bool {
	enc := r.Header.Get("Grpc-Encoding")
	return enc != "" && enc != "identity" && enc != "gzip"
}

// grpcPlainMessages rewrites a gRPC request body with each message uncompressed, so every byte the broker checks is a byte the upstream reads.
// A body not splitting into whole messages, or a message that does not decompress, is refused as request_shape; past limit, request_too_large.
func grpcPlainMessages(body []byte, encoding string, limit int64) ([]byte, string) {
	out := make([]byte, 0, len(body))
	for len(body) > 0 {
		if len(body) < 5 {
			return nil, "request_shape"
		}
		flag, size := body[0], binary.BigEndian.Uint32(body[1:5])
		if uint64(len(body)-5) < uint64(size) {
			return nil, "request_shape"
		}
		message := body[5 : 5+size]
		body = body[5+size:]
		switch {
		case flag == 1 && encoding == "gzip":
			zr, err := gzip.NewReader(bytes.NewReader(message))
			if err != nil {
				return nil, "request_shape"
			}
			room := limit - int64(len(out)) - 5
			if room < 0 {
				return nil, "request_too_large"
			}
			message, err = io.ReadAll(io.LimitReader(zr, room+1))
			if err != nil {
				return nil, "request_shape"
			}
		case flag != 0:
			return nil, "request_shape"
		}
		if int64(len(out))+5+int64(len(message)) > limit {
			return nil, "request_too_large"
		}
		out = append(out, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint32(out[len(out)-4:], uint32(len(message))) // #nosec G115 -- bounded by limit, at most 1 GiB
		out = append(out, message...)
	}
	return out, ""
}

func grpcBodyStatus(outcome string) int {
	if outcome == "request_too_large" {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

// authorityMatches reports whether a request inside a tunnel names the tunnel's host: target itself, the host alone on the scheme's default port, or over HTTP/2 the host alone on any port, as gRPC clients often send it.
func authorityMatches(r *http.Request, target string) bool {
	if r.Host == target || r.Host == hostHeaderForScheme("https", target) {
		return true
	}
	host, _, err := net.SplitHostPort(target)
	return err == nil && viaHTTP2(r.Context()) && r.Host == host
}

// prepareGRPC sets the headers the broker owns: te, and an uncompressed response so every returned byte is screened.
func prepareGRPC(out *http.Request) {
	out.Header.Set("Te", "trailers")
	out.Header.Set("Grpc-Accept-Encoding", "identity")
}

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

// grpcStatusFor maps the HTTP status of a broker refusal or non-gRPC upstream answer to a gRPC status; a passing refusal (Retry-After) is UNAVAILABLE, which clients retry, and a lasting 503 is FAILED_PRECONDITION, which they do not.
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

// maxGRPCMessage bounds grpc-message: clients refuse response metadata past 8 KiB.
const maxGRPCMessage = 1024

// grpcWriter answers a refusal or upstream HTTP error the way gRPC clients read a failure: status 200, no messages, grpc-status and grpc-message trailers.
// The refusal code stays in RefusalHeader; a 200 passes through untouched.
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
		// An upstream error page or a broker transport error: say which status, never the body.
		h.Set(http.TrailerPrefix+"Grpc-Message", grpcMessage("HTTP "+strconv.Itoa(status)+" "+http.StatusText(status)))
	}
}

// Write passes a 200's body through; after a refusal it keeps the broker's text as grpc-message.
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

// fail ends a call already streaming with a gRPC status in its trailers, so the client discards what it has.
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

// grpcMessage percent-encodes text for grpc-message, as the wire format requires.
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

// grpcCallStatus is the grpc-status a response ended with, or -1.
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

type grpcFrames struct {
	header     [5]byte
	have       int    // header bytes read for the current message
	left       uint32 // message bytes still to come
	compressed bool   // a message set the compression flag
}

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

// framesSafe reports whether no needle holds a byte a message header can start with, so no needle straddles a message boundary.
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

// upstreamFor is the transport for an upstream request: HTTP/2 only when the worker's request arrived over HTTP/2, else HTTP/1.1; a request presenting a client certificate takes that certificate's transport (clientcert.go).
func (p *Proxy) upstreamFor(out *http.Request) http.RoundTripper {
	h2 := viaHTTP2(out.Context())
	if presented, ok := clientCertificateFrom(out.Context()); ok {
		return p.certificateUpstream(presented, h2)
	}
	if !h2 {
		return p.upstream
	}
	if t := p.h2Upstream.Load(); t != nil {
		return t
	}
	t := p.newUpstream(true)
	if p.h2Upstream.CompareAndSwap(nil, t) {
		return t
	}
	return p.h2Upstream.Load()
}

// newUpstream builds a transport from the HTTP/1.1 one, with its dialer, egress checks and TLS verification.
func (p *Proxy) newUpstream(h2 bool) *http.Transport {
	t := p.upstream.Clone()
	if !h2 {
		return t
	}
	t.Protocols = new(http.Protocols)
	t.Protocols.SetHTTP2(true)
	// Calls share connections. Strict mode turns off HTTP/1.1 keep-alives so a request is never resent on a reused connection; without HTTP/1.1 here, an upstream not offering HTTP/2 fails the call.
	t.DisableKeepAlives = false
	return t
}

// grpcCompressedResponse reports a response that compresses despite the broker asking for none; it could not be screened.
func grpcCompressedResponse(h http.Header) bool {
	enc := h.Get("Grpc-Encoding")
	return enc != "" && enc != "identity"
}

func grpcStreamStatus(outcome string) int {
	switch outcome {
	case "response_too_large":
		return grpcResourceExhausted
	case "upstream_error":
		return grpcUnavailable
	}
	return grpcInternal
}
