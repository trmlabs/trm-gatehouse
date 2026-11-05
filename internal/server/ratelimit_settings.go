package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Infisical/agent-vault/internal/ratelimit"
)

// rateLimitSettingPayload is the stored rate-limit setting: a profile plus optional per-tier overrides (empty inherits).
type rateLimitSettingPayload struct {
	Profile   string                           `json:"profile"`
	Overrides map[string]rateLimitTierOverride `json:"overrides,omitempty"`
}

// rateLimitTierOverride mirrors ratelimit.TierConfig but uses a JSON-
// friendly duration string for Window. All fields are optional.
type rateLimitTierOverride struct {
	Rate        *float64 `json:"rate,omitempty"`
	Burst       *int     `json:"burst,omitempty"`
	Window      string   `json:"window,omitempty"` // RFC: e.g. "5m", "1h"
	Max         *int     `json:"max,omitempty"`
	Concurrency *int     `json:"concurrency,omitempty"`
}

// loadRateLimitSetting returns the parsed setting payload, or a
// zero-value payload if the setting is absent.
func loadRateLimitSetting(ctx context.Context, s Store) (rateLimitSettingPayload, bool, error) {
	raw, err := s.GetSetting(ctx, settingRateLimitConfig)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rateLimitSettingPayload{}, false, nil
		}
		return rateLimitSettingPayload{}, false, err
	}
	if raw == "" {
		return rateLimitSettingPayload{}, false, nil
	}
	var p rateLimitSettingPayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return rateLimitSettingPayload{}, false, fmt.Errorf("parse ratelimit_config: %w", err)
	}
	return p, true, nil
}

// resolveRateLimitConfig computes the effective Config: env > instance setting > default; AGENT_VAULT_RATELIMIT_LOCK ignores the setting.
func resolveRateLimitConfig(ctx context.Context, s Store) (ratelimit.Config, rateLimitSettingPayload, bool, ratelimit.EnvMasks, error) {
	envCfg, envMask := ratelimit.LoadFromEnv()
	if envCfg.Locked {
		return envCfg, rateLimitSettingPayload{}, false, envMask, nil
	}
	payload, present, err := loadRateLimitSetting(ctx, s)
	if err != nil {
		return envCfg, rateLimitSettingPayload{}, false, envMask, err
	}
	if !present {
		return envCfg, payload, false, envMask, nil
	}
	return applyPayload(envCfg, envMask, payload), payload, true, envMask, nil
}

// applyPayload layers a payload on an env-derived base, re-asserting envMask knobs; no DB reads.
func applyPayload(envCfg ratelimit.Config, envMask ratelimit.EnvMasks, payload rateLimitSettingPayload) ratelimit.Config {
	base := envCfg
	if payload.Profile != "" {
		base = ratelimit.DefaultsFor(ratelimit.Profile(payload.Profile))
		base.Locked = envCfg.Locked
		// DefaultsFor wiped the env knobs; copy them back from envCfg.
		for _, t := range ratelimit.AllTiers() {
			if envMask[t].Rate {
				base.Tiers[t].Rate = envCfg.Tiers[t].Rate
			}
			if envMask[t].Burst {
				base.Tiers[t].Burst = envCfg.Tiers[t].Burst
			}
			if envMask[t].Window {
				base.Tiers[t].Window = envCfg.Tiers[t].Window
			}
			if envMask[t].Max {
				base.Tiers[t].Max = envCfg.Tiers[t].Max
			}
			if envMask[t].Concurrency {
				base.Tiers[t].Concurrency = envCfg.Tiers[t].Concurrency
			}
		}
	}

	overrides := map[ratelimit.Tier]ratelimit.TierConfig{}
	for name, ov := range payload.Overrides {
		tier, ok := ratelimit.TierByName(name)
		if !ok {
			continue
		}
		tc := ratelimit.TierConfig{}
		if ov.Rate != nil {
			tc.Rate = *ov.Rate
		}
		if ov.Burst != nil {
			tc.Burst = *ov.Burst
		}
		if ov.Window != "" {
			if d, err := time.ParseDuration(ov.Window); err == nil {
				tc.Window = d
			}
		}
		if ov.Max != nil {
			tc.Max = *ov.Max
		}
		if ov.Concurrency != nil {
			tc.Concurrency = *ov.Concurrency
		}
		overrides[tier] = tc
	}
	base.ApplyOverrides(overrides)
	return base
}

// rateLimitSourceForTier returns "env", "override", or "default" so
// the UI can show which layer supplied each tier's current values.
func rateLimitSourceForTier(t ratelimit.Tier, payload rateLimitSettingPayload, hasPayload bool, envMask ratelimit.EnvMasks) string {
	if envMask[t].Any() {
		return "env"
	}
	if hasPayload {
		if _, ok := payload.Overrides[t.String()]; ok {
			return "override"
		}
	}
	return "default"
}

// applyRateLimitSettingToRegistry reloads the registry from the current setting and env, at startup and after each settings write.
func (s *Server) applyRateLimitSettingToRegistry(ctx context.Context) (ratelimit.Config, error) {
	cfg, _, _, _, err := resolveRateLimitConfig(ctx, s.store)
	if err != nil {
		return cfg, err
	}
	s.rateLimit.Reload(cfg)
	return cfg, nil
}

// tierJSON is one tier's effective config in GET /v1/admin/settings; Source is env, override or default.
type tierJSON struct {
	Rate        float64 `json:"rate,omitempty"`
	Burst       int     `json:"burst,omitempty"`
	Window      string  `json:"window,omitempty"`
	Max         int     `json:"max,omitempty"`
	Concurrency int     `json:"concurrency,omitempty"`
	Source      string  `json:"source"`
}

// buildRateLimitSettingResponse assembles the rate_limit settings field; nil on a hard error so the rest of the response still works.
func (s *Server) buildRateLimitSettingResponse(ctx context.Context) map[string]interface{} {
	cfg, payload, hasPayload, envMask, err := resolveRateLimitConfig(ctx, s.store)
	if err != nil {
		return nil
	}
	return buildRateLimitResponse(cfg, payload, hasPayload, envMask)
}

// buildRateLimitResponse serializes the config; split out so the preview handler avoids a DB read.
func buildRateLimitResponse(cfg ratelimit.Config, payload rateLimitSettingPayload, hasPayload bool, envMask ratelimit.EnvMasks) map[string]interface{} {
	all := ratelimit.AllTiers()
	tiers := make(map[string]tierJSON, len(all))
	for _, t := range all {
		tc := cfg.Tiers[t]
		tiers[t.String()] = tierJSON{
			Rate:        tc.Rate,
			Burst:       tc.Burst,
			Window:      formatDuration(tc.Window),
			Max:         tc.Max,
			Concurrency: tc.Concurrency,
			Source:      rateLimitSourceForTier(t, payload, hasPayload, envMask),
		}
	}
	profile := string(cfg.Profile)
	if payload.Profile != "" {
		profile = payload.Profile
	}
	return map[string]interface{}{
		"profile": profile,
		"locked":  cfg.Locked,
		"off":     cfg.Off,
		"tiers":   tiers,
	}
}

// handleRateLimitPreview computes the effective config for a payload without persisting it.
func (s *Server) handleRateLimitPreview(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}
	envCfg, envMask := ratelimit.LoadFromEnv()
	if envCfg.Locked {
		jsonError(w, http.StatusConflict, "Rate-limit config is pinned by operator env var")
		return
	}
	var p rateLimitSettingPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	cfg := applyPayload(envCfg, envMask, p)
	jsonOK(w, buildRateLimitResponse(cfg, p, true, envMask))
}

func formatDuration(d time.Duration) string {
	if d == 0 {
		return ""
	}
	return d.String()
}

// handleUpdateRateLimitSetting validates and persists a rate-limit payload, then reloads the registry.
func (s *Server) handleUpdateRateLimitSetting(ctx context.Context, p *rateLimitSettingPayload) error {
	if s.rateLimit.Config().Locked {
		return ratelimit.ErrLocked
	}
	if p == nil {
		return fmt.Errorf("rate_limit payload is required")
	}

	// Validate profile if present.
	if p.Profile != "" {
		switch ratelimit.Profile(p.Profile) {
		case ratelimit.ProfileDefault, ratelimit.ProfileStrict, ratelimit.ProfileLoose, ratelimit.ProfileOff:
		default:
			return fmt.Errorf("invalid profile %q (default|strict|loose|off)", p.Profile)
		}
	}

	// Validate the overrides against fixed clamps before layering them
	// onto a candidate config through the shared applyPayload helper.
	for name, ov := range p.Overrides {
		if _, ok := ratelimit.TierByName(name); !ok {
			return fmt.Errorf("unknown tier %q", name)
		}
		if ov.Rate != nil && (*ov.Rate < 0 || *ov.Rate > 100000) {
			return fmt.Errorf("tier %s: rate %.1f out of range (0-100000)", name, *ov.Rate)
		}
		if ov.Burst != nil && (*ov.Burst < 0 || *ov.Burst > 100000) {
			return fmt.Errorf("tier %s: burst %d out of range (0-100000)", name, *ov.Burst)
		}
		if ov.Max != nil && (*ov.Max < 0 || *ov.Max > 100000) {
			return fmt.Errorf("tier %s: max %d out of range (0-100000)", name, *ov.Max)
		}
		if ov.Concurrency != nil && (*ov.Concurrency < 0 || *ov.Concurrency > 8192) {
			return fmt.Errorf("tier %s: concurrency %d out of range (0-8192)", name, *ov.Concurrency)
		}
		if ov.Window != "" {
			if _, err := time.ParseDuration(ov.Window); err != nil {
				return fmt.Errorf("tier %s: window %q: %w", name, ov.Window, err)
			}
		}
	}
	envCfg, envMask := ratelimit.LoadFromEnv()
	candidate := applyPayload(envCfg, envMask, *p)
	if err := candidate.Validate(); err != nil {
		return err
	}

	// Store the caller's payload as-is so the UI can round-trip values.
	encoded, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("encode ratelimit_config: %w", err)
	}
	if err := s.store.SetSetting(ctx, settingRateLimitConfig, string(encoded)); err != nil {
		return fmt.Errorf("save ratelimit_config: %w", err)
	}
	if _, err := s.applyRateLimitSettingToRegistry(ctx); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return nil
}
