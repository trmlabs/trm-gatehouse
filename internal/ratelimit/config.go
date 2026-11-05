package ratelimit

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Profile is a named bundle of tier defaults.
type Profile string

const (
	ProfileDefault Profile = "default"
	ProfileStrict  Profile = "strict"
	ProfileLoose   Profile = "loose"
	ProfileOff     Profile = "off"
)

// TierConfig holds the tunables for a single tier. Zero values mean
// "unset"; resolution layers fill them in.
type TierConfig struct {
	Algorithm   Algorithm
	Rate        float64       // tokens/sec (bucket) or events/window (sliding)
	Burst       int           // bucket depth
	Window      time.Duration // sliding window
	Max         int           // sliding max events per window
	Concurrency int           // semaphore cap
	MaxKeys     int           // per-limiter map cap (LRU evict)
}

// Config is the resolved per-tier configuration for a Registry; Off allows everything.
type Config struct {
	Profile Profile
	Off     bool
	Locked  bool // true when AGENT_VAULT_RATELIMIT_LOCK=true
	Tiers   [tierCount]TierConfig
}

// DefaultsFor returns a Config populated with the requested profile's
// baselines.
func DefaultsFor(profile Profile) Config {
	var c Config
	c.Profile = profile
	if profile == ProfileOff {
		c.Off = true
		return c
	}
	mul := profileMultiplier(profile)
	// Unauthenticated surface, including proxy auth failures keyed per address or attested sandbox.
	c.Tiers[TierAuth] = TierConfig{
		Algorithm: AlgSliding, Window: 5 * time.Minute, Max: scaleMax(50, mul), MaxKeys: defaultMaxKeys,
	}
	// MITM proxy: Concurrency caps in-flight upstream calls per (actor and workload, vault); sized for parallel fan-out.
	c.Tiers[TierProxy] = TierConfig{
		Algorithm: AlgTokenBucket, Rate: scaleRate(200.0, mul), Burst: scaleMax(2000, mul),
		Concurrency: scaleMax(1024, mul), MaxKeys: defaultMaxKeys,
	}
	// Everything behind requireAuth — generous; the heaviest legitimate
	// agent workload can be several discover+CRUD bursts per minute.
	c.Tiers[TierAuthed] = TierConfig{
		Algorithm: AlgTokenBucket, Rate: scaleRate(10.0, mul), Burst: scaleMax(240, mul), MaxKeys: defaultMaxKeys,
	}
	// Server-wide backstop sized for 10,000 workers on one replica at about two requests a second each.
	c.Tiers[TierGlobal] = TierConfig{
		Rate: float64(scaleMax(20000, mul)), Burst: scaleMax(40000, mul),
		Concurrency: scaleMax(10000, mul),
	}
	// Internal: failure counter for verification codes.
	c.Tiers[TierVerifyFailure] = TierConfig{
		Algorithm: AlgFailureCounter, Max: scaleMax(10, mul), MaxKeys: defaultMaxKeys,
	}
	return c
}

// defaultMaxKeys is how many keys each keyed tier tracks before evicting the coldest; an evicted key restarts with a full bucket.
const defaultMaxKeys = 200000

func profileMultiplier(p Profile) float64 {
	switch p {
	case ProfileStrict:
		return 0.5
	case ProfileLoose:
		return 2.0
	default:
		return 1.0
	}
}

func scaleMax(base int, mul float64) int {
	v := int(float64(base) * mul)
	if v < 1 {
		v = 1
	}
	return v
}

func scaleRate(base, mul float64) float64 {
	v := base * mul
	if v <= 0 {
		v = 0.1
	}
	return v
}

// EnvSetMask records which per-tier env knobs were explicitly set.
type EnvSetMask struct {
	Rate, Burst, Window, Max, Concurrency bool
}

// EnvMasks is the per-tier mask array returned by LoadFromEnv. Named
// so callers can hold it in a variable without referencing tierCount.
type EnvMasks [tierCount]EnvSetMask

// LoadFromEnv returns a Config from the environment plus a mask of env-set knobs; AGENT_VAULT_RATELIMIT_LOCK=true pins it against UI overrides.
func LoadFromEnv() (Config, EnvMasks) {
	profile := Profile(strings.ToLower(os.Getenv("AGENT_VAULT_RATELIMIT_PROFILE")))
	if profile == "" {
		profile = ProfileDefault
	}
	cfg := DefaultsFor(profile)
	cfg.Locked = strings.EqualFold(os.Getenv("AGENT_VAULT_RATELIMIT_LOCK"), "true")
	var mask EnvMasks
	if cfg.Off {
		return cfg, mask
	}
	for t := Tier(0); t < tierCount; t++ {
		prefix := "AGENT_VAULT_RATELIMIT_" + t.String() + "_"
		if v := os.Getenv(prefix + "RATE"); v != "" {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				cfg.Tiers[t].Rate = f
				mask[t].Rate = true
			}
		}
		if v := os.Getenv(prefix + "BURST"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				cfg.Tiers[t].Burst = n
				mask[t].Burst = true
			}
		}
		if v := os.Getenv(prefix + "WINDOW"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				cfg.Tiers[t].Window = d
				mask[t].Window = true
			}
		}
		if v := os.Getenv(prefix + "MAX"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				cfg.Tiers[t].Max = n
				mask[t].Max = true
			}
		}
		if v := os.Getenv(prefix + "CONCURRENCY"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				cfg.Tiers[t].Concurrency = n
				mask[t].Concurrency = true
			}
		}
	}
	return cfg, mask
}

// EnvSet reports whether any of a tier's knobs were set via env.
func (m EnvSetMask) Any() bool {
	return m.Rate || m.Burst || m.Window || m.Max || m.Concurrency
}

// ApplyOverrides merges partial overrides into c; callers must gate on Locked first.
func (c *Config) ApplyOverrides(overrides map[Tier]TierConfig) {
	for t, ov := range overrides {
		if t < 0 || t >= tierCount {
			continue
		}
		if ov.Rate != 0 {
			c.Tiers[t].Rate = ov.Rate
		}
		if ov.Burst != 0 {
			c.Tiers[t].Burst = ov.Burst
		}
		if ov.Window != 0 {
			c.Tiers[t].Window = ov.Window
		}
		if ov.Max != 0 {
			c.Tiers[t].Max = ov.Max
		}
		if ov.Concurrency != 0 {
			c.Tiers[t].Concurrency = ov.Concurrency
		}
	}
}

// Validate returns a non-nil error if c would produce a server the
// operator cannot recover from (e.g. auth limits set to 0).
func (c *Config) Validate() error {
	if c.Off {
		return nil
	}
	if c.Tiers[TierAuth].Max < minAuthFloor {
		return fmt.Errorf("AUTH.max below floor (%d): owner lockout risk", minAuthFloor)
	}
	if c.Tiers[TierGlobal].Concurrency < minGlobalInflight {
		return fmt.Errorf("GLOBAL.concurrency below floor (%d)", minGlobalInflight)
	}
	if c.Tiers[TierGlobal].Rate < float64(minGlobalRPS) {
		return fmt.Errorf("GLOBAL.rate below floor (%d)", minGlobalRPS)
	}
	return nil
}

// Floors enforced by Validate. Env vars can go below them (for
// deliberate testing); UI overrides cannot.
const (
	minAuthFloor      = 5
	minGlobalInflight = 32
	minGlobalRPS      = 100
)
