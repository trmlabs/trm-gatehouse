package server

import (
	"net"
	"net/http"
)

// handleMITMCA serves the public transparent-proxy root CA in PEM form, only while the proxy is listening.
// The X-MITM-Port header advertises the bound port so non-default --mitm-port values work.
func (s *Server) handleMITMCA(w http.ResponseWriter, _ *http.Request) {
	if s.mitm == nil || !s.mitm.IsListening() {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("MITM proxy is not enabled on this server\n"))
		return
	}
	if _, port, err := net.SplitHostPort(s.mitm.Addr()); err == nil && port != "" && port != "0" {
		w.Header().Set("X-MITM-Port", port)
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="agent-vault-ca.pem"`)
	_, _ = w.Write(s.mitm.RootPEM())
}
