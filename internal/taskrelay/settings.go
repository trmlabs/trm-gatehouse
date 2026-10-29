package taskrelay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// AutomationSettingsConfig, in self mode only, has a Cursor worker's sidecar
// write the plain settings the broker's catalog lists for the Automation that
// started the claimed run (httpcatalog.CheckSetting) to File, as shell export
// lines, where the agent's shells read them: the worker points BASH_ENV at a
// loader that sources the file. The worker mounts File's directory read-only.
//
// Once the run's identity socket is up, the sidecar asks the broker with the
// run's token, the one it relays on each connection, so the broker answers
// for the run this Pod was started for and no other. It asks again every
// RefreshSeconds, so a catalog change reaches shells started after it.
//
// The file is replaced whole (written beside it, then renamed), so a shell
// reads either the old file or the new one. A shell waits only for the file
// to exist, so it always exists within WaitSeconds of the sidecar starting:
// without the broker's answer by then, or when the broker refuses the run,
// the file prints one line on stderr saying the settings are unavailable,
// and the sidecar keeps asking. A later answer replaces it.
type AutomationSettingsConfig struct {
	File string `json:"file"`
	// WaitSeconds bounds how long the file may be missing after the sidecar
	// starts (default 180, 1 to 3600). It covers the identity socket, which
	// can appear a minute or more after the worker starts.
	WaitSeconds int `json:"waitSeconds,omitempty"`
	// RefreshSeconds is how often the settings are read again (default 300,
	// 30 to 86400).
	RefreshSeconds int `json:"refreshSeconds,omitempty"`
}

const (
	defaultSettingsWait    = 180
	defaultSettingsRefresh = 300
	// settingsResponseLimit bounds the broker's answer: the largest settings
	// the catalog allows, with room for JSON escaping.
	settingsResponseLimit = 8 * httpcatalog.MaxSettingsMaxBytes
	settingsRetryMax      = 30 * time.Second
	sessionHeader         = "Gatehouse-Session"
)

func (s *AutomationSettingsConfig) validate(c FixedConfig) error {
	// Only a sidecar relaying a Cursor run's token can name an Automation.
	if !c.Self || c.Shared != nil || c.Connect == nil || c.Connect.Upstream.SessionSocketDir == "" {
		return errConfig
	}
	if !filepath.IsAbs(s.File) || filepath.Clean(s.File) != s.File || filepath.Dir(s.File) == "/" || strings.ContainsAny(s.File, "\r\n") {
		return errConfig
	}
	if s.WaitSeconds < 0 || s.WaitSeconds > 3600 || (s.RefreshSeconds != 0 && (s.RefreshSeconds < 30 || s.RefreshSeconds > 86400)) {
		return errConfig
	}
	return nil
}

func (s *AutomationSettingsConfig) wait() time.Duration {
	if s.WaitSeconds == 0 {
		return defaultSettingsWait * time.Second
	}
	return time.Duration(s.WaitSeconds) * time.Second
}

func (s *AutomationSettingsConfig) refresh() time.Duration {
	if s.RefreshSeconds == 0 {
		return defaultSettingsRefresh * time.Second
	}
	return time.Duration(s.RefreshSeconds) * time.Second
}

// errSettings is a broker answer the sidecar does not accept.
var errSettings = errors.New("invalid settings answer")

// settingsWriter keeps File current for the run.
type settingsWriter struct {
	config AutomationSettingsConfig
	log    *slog.Logger
	// token is the run's identity token, "" before the claim; fetch asks
	// the broker with it and returns the HTTP status and, on 200, the
	// settings.
	token func() string
	fetch func(ctx context.Context, token string) (int, map[string]string, error)
	// tick is the shortest wait between attempts.
	tick time.Duration
}

func newSettingsWriter(c FixedConfig, log *slog.Logger) *settingsWriter {
	upstream := c.Connect.Upstream
	return &settingsWriter{config: *c.AutomationSettings, log: log, tick: time.Second,
		token: func() string { return readSession(log, upstream) },
		fetch: func(ctx context.Context, token string) (int, map[string]string, error) {
			return fetchSettings(ctx, upstream, c.Deadline, token)
		}}
}

// run keeps the file current until ctx ends. Before the claim it looks for
// the run's token every tick; after a failed answer it asks again after a
// growing wait, up to settingsRetryMax; after an answer or a refusal, every
// refresh, since a refused run stays refused and each ask is an audited
// refusal.
func (s *settingsWriter) run(ctx context.Context) {
	started := time.Now()
	written, served := false, false
	retry := s.tick
	for {
		next := s.tick // no claim yet
		if token := s.token(); token != "" {
			next, retry = retry, min(retry*2, settingsRetryMax)
			status, settings, err := s.fetch(ctx, token)
			switch {
			case err == nil && status == http.StatusOK:
				if e := writeSettingsFile(s.config.File, settingsScript(settings)); e != nil {
					s.log.Warn("settings_write_failed", "error", e.Error())
					break
				}
				if !served {
					s.log.Info("settings_written", "settings", len(settings), "names", strings.Join(httpcatalog.SettingNames(settings), ","),
						"afterMs", time.Since(started).Milliseconds())
				}
				written, served = true, true
				next, retry = s.config.refresh(), s.tick
			case err == nil && status == http.StatusForbidden:
				// A refused run is refused everything, so its settings go too.
				s.log.Warn("settings_refused")
				if writeSettingsFile(s.config.File, noticeScript("refused by the broker")) == nil {
					written, served = true, false
				}
				next, retry = s.config.refresh(), s.tick
			default:
				s.log.Warn("settings_unavailable", "status", status, "error", errorText(err))
			}
		}
		if !written {
			left := s.config.wait() - time.Since(started)
			if left <= 0 && writeSettingsFile(s.config.File, noticeScript("no answer from the broker yet")) == nil {
				written = true
				s.log.Warn("settings_wait_expired", "afterMs", time.Since(started).Milliseconds())
			}
			next = min(next, max(left, s.tick))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// fetchSettings asks the broker for the run's Automation settings, proving
// this Pod as a CONNECT does and relaying the run's token. It returns the
// status and, on 200, settings that pass the catalog's own checks.
func fetchSettings(ctx context.Context, upstream UpstreamConfig, deadline time.Time, token string) (int, map[string]string, error) {
	proof, _, e := readProof(upstream, deadline)
	if e != nil {
		return 0, nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, brokerRequestTimeout)
	defer cancel()
	conn, e := dialUpstream(ctx, upstream)
	if e != nil {
		return 0, nil, e
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+upstream.ServerName+httpcatalog.SettingsPath, nil)
	if e != nil {
		return 0, nil, e
	}
	req.Header.Set("Proxy-Authorization", "Bearer "+proof)
	req.Header.Set(sessionHeader, token)
	req.Close = true
	if e = req.Write(conn); e != nil {
		return 0, nil, e
	}
	resp, e := http.ReadResponse(bufio.NewReader(conn), req)
	if e != nil {
		return 0, nil, e
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, nil
	}
	body, e := io.ReadAll(io.LimitReader(resp.Body, settingsResponseLimit+1))
	if e != nil {
		return resp.StatusCode, nil, e
	}
	var answer struct {
		Settings map[string]string `json:"settings"`
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if len(body) > settingsResponseLimit || d.Decode(&answer) != nil || d.More() || answer.Settings == nil {
		return resp.StatusCode, nil, errSettings
	}
	// The broker checked them against its catalog; the sidecar checks the
	// shape again before anything reaches a shell.
	if httpcatalog.CheckSettings(answer.Settings, httpcatalog.MaxSettingsMaxBytes) != nil {
		return resp.StatusCode, nil, errSettings
	}
	return resp.StatusCode, answer.Settings, nil
}

// settingsScript is the file for served settings: one export per setting, in
// name order, each value single-quoted so a shell takes it literally. The
// names and values passed httpcatalog.CheckSettings: plain names, no control
// characters.
func settingsScript(settings map[string]string) []byte {
	var b strings.Builder
	b.WriteString("# This run's Automation settings, from the Gatehouse catalog. Written by the Gatehouse sidecar.\n")
	for _, name := range httpcatalog.SettingNames(settings) {
		b.WriteString("export " + name + "=" + shellQuote(settings[name]) + "\n")
	}
	return []byte(b.String())
}

// noticeScript is the file when there are no settings to give: it sets
// nothing and says why on stderr, once per shell. reason is one of the
// sidecar's own fixed phrases.
func noticeScript(reason string) []byte {
	return []byte("# No Automation settings for this run. Written by the Gatehouse sidecar.\n" +
		"printf '%s\\n' " + shellQuote("gatehouse: this run's Automation settings are unavailable ("+reason+"); the shell starts without them") + " >&2\n")
}

func shellQuote(v string) string { return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" }

// writeSettingsFile replaces path whole: the content goes to a new file
// beside it, which is then renamed over it, so a reader sees the old file or
// the new one and never part of either.
func writeSettingsFile(path string, content []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
