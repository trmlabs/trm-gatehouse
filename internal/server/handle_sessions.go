package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Infisical/agent-vault/internal/store"
)

type scopedSessionRequest struct {
	Vault      string `json:"vault"`
	VaultRole  string `json:"vault_role"`
	TTLSeconds *int   `json:"ttl_seconds,omitempty"`
	Label      string `json:"label,omitempty"`
}

type scopedSessionResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	AVAddr    string `json:"av_addr,omitempty"`
}

// scopedSessionView is the JSON projection for GET /v1/sessions; the raw token is never re-readable.
type scopedSessionView struct {
	ID        string                  `json:"id"`
	Label     string                  `json:"label,omitempty"`
	VaultRole string                  `json:"vault_role"`
	CreatedBy *scopedSessionActorView `json:"created_by,omitempty"`
	CreatedAt string                  `json:"created_at"`
	ExpiresAt string                  `json:"expires_at,omitempty"`
}

type scopedSessionActorView struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name"`
}

// maxScopedSessionLabel caps the user-supplied label length to protect the Tokens UI layout.
const maxScopedSessionLabel = 100

// sanitizeScopedSessionLabel trims whitespace and strips ASCII control characters; the caller rejects over-long labels.
func sanitizeScopedSessionLabel(label string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return ""
	}
	cleaned := make([]rune, 0, len(label))
	for _, r := range label {
		if r < 0x20 || r == 0x7f {
			continue
		}
		cleaned = append(cleaned, r)
	}
	return string(cleaned)
}

func (s *Server) handleScopedSession(w http.ResponseWriter, r *http.Request) {
	var req scopedSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Vault == "" {
		jsonError(w, http.StatusBadRequest, "Vault is required")
		return
	}

	// Tokens are minted with role `proxy` only; requireVaultMember below enforces the member+ caller floor.
	if req.VaultRole != "" && req.VaultRole != "proxy" {
		jsonError(w, http.StatusBadRequest, "vault_role must be 'proxy'")
		return
	}

	// Validate TTL bounds if provided.
	if req.TTLSeconds != nil {
		ttl := time.Duration(*req.TTLSeconds) * time.Second
		if ttl < scopedSessionMinTTL || ttl > scopedSessionMaxTTL {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf(
				"ttl_seconds must be between %d and %d",
				int(scopedSessionMinTTL.Seconds()), int(scopedSessionMaxTTL.Seconds()),
			))
			return
		}
	}

	// Control chars would break the Tokens table; length is counted in runes to match the frontend maxLength.
	req.Label = sanitizeScopedSessionLabel(req.Label)
	if utf8.RuneCountInString(req.Label) > maxScopedSessionLabel {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf(
			"label must be at most %d characters", maxScopedSessionLabel,
		))
		return
	}

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	// Caller must be at least a vault `member`; proxy-role callers can only proxy requests.
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}
	parentSess := sessionFromContext(ctx)

	// vault_role is locked to "proxy", so no role-cap check is needed; restore one if other roles are enabled.
	cappedRole := "proxy"

	// Compute expiry: use ttl_seconds if provided, otherwise default 24h.
	var expiresAt *time.Time
	if req.TTLSeconds != nil {
		t := time.Now().Add(time.Duration(*req.TTLSeconds) * time.Second)
		expiresAt = &t
	} else {
		t := time.Now().Add(scopedSessionDefaultTTL)
		expiresAt = &t
	}

	// A nil actor means the caller is itself a scoped session; leave created_by blank rather than fail.
	var createdByID, createdByType string
	if actor, err := s.actorFromSession(ctx, parentSess); err == nil && actor != nil {
		createdByID = actor.ID
		createdByType = actor.Type
	}

	sess, err := s.store.CreateScopedSession(ctx, store.CreateScopedSessionParams{
		VaultID:            ns.ID,
		VaultRole:          cappedRole,
		ExpiresAt:          expiresAt,
		Label:              req.Label,
		CreatedByActorID:   createdByID,
		CreatedByActorType: createdByType,
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create scoped session")
		return
	}

	jsonOK(w, scopedSessionResponse{
		Token:     sess.ID,
		ExpiresAt: formatExpiresAt(sess.ExpiresAt),
		AVAddr:    s.baseURL,
	})
}

// handleListScopedSessions lists a vault's active scoped tokens, newest first; vault `member`+ only since created_by identifies minters.
func (s *Server) handleListScopedSessions(w http.ResponseWriter, r *http.Request) {
	vaultName := r.URL.Query().Get("vault")
	if vaultName == "" {
		jsonError(w, http.StatusBadRequest, "vault is required")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, vaultName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	rows, err := s.store.ListScopedSessionsByVault(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list scoped sessions")
		return
	}

	displayNames := make(map[string]string, len(rows))
	out := make([]scopedSessionView, 0, len(rows))
	for _, sess := range rows {
		view := scopedSessionView{
			ID:        sess.PublicID,
			Label:     sess.Label,
			VaultRole: sess.VaultRole,
			CreatedAt: formatExpiresAt(&sess.CreatedAt),
			ExpiresAt: formatExpiresAt(sess.ExpiresAt),
		}
		if sess.CreatedByActorID != "" && sess.CreatedByActorType != "" {
			cacheKey := sess.CreatedByActorType + ":" + sess.CreatedByActorID
			displayName, ok := displayNames[cacheKey]
			if !ok {
				if actor, err := s.actorByID(ctx, sess.CreatedByActorID, sess.CreatedByActorType); err == nil {
					displayName = actor.DisplayLabel()
				} else {
					displayName = sess.CreatedByActorID
				}
				displayNames[cacheKey] = displayName
			}
			view.CreatedBy = &scopedSessionActorView{
				ID:          sess.CreatedByActorID,
				Type:        sess.CreatedByActorType,
				DisplayName: displayName,
			}
		}
		out = append(out, view)
	}
	jsonOK(w, map[string]interface{}{"sessions": out})
}

// handleRevokeScopedSession deletes a scoped token by public_id; vault `member`+ only, and the store filters by vault_id.
func (s *Server) handleRevokeScopedSession(w http.ResponseWriter, r *http.Request) {
	publicID := r.PathValue("id")
	if publicID == "" {
		jsonError(w, http.StatusBadRequest, "Session id is required")
		return
	}

	vaultName := r.URL.Query().Get("vault")
	if vaultName == "" {
		jsonError(w, http.StatusBadRequest, "vault is required")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, vaultName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	err = s.store.RevokeScopedSession(ctx, ns.ID, publicID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "Session not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to revoke scoped session")
		return
	}
	jsonOK(w, map[string]string{"status": "revoked"})
}
