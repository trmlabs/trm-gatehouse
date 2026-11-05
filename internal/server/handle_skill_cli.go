package server

import "net/http"

// The embedded agent skill served at GET /v1/skills/cli, compiled from cmd/skill_cli.md.
// Instance-wide, unauthenticated, read-only; unrelated to the per-vault Skills resource.

// SetSkillCLI sets the embedded CLI skill content.
func (s *Server) SetSkillCLI(cli string) {
	s.skillCLI = []byte(cli)
}

func (s *Server) handleSkillCLI(w http.ResponseWriter, r *http.Request) {
	if len(s.skillCLI) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	_, _ = w.Write(s.skillCLI)
}
