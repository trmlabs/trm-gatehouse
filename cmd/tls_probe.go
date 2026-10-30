package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var tlsProbeCmd = &cobra.Command{
	Use:   "tls-probe [target...]",
	Short: "Check TLS handshakes to upstreams from this build",
	Long: `tls-probe runs a TLS handshake to each target from inside this build, so a
FIPS image can be checked against every upstream before it is rolled out. Targets
are arguments or one per line on stdin: host:port for direct TLS (Neo4j bolt+s
included), postgres://host:port (SSLRequest, then TLS) and smtp://host:port
(STARTTLS). Certificates are verified against the system roots the broker uses
for upstream connections, plus --ca-file when given. Each target prints one line
with the TLS version, cipher suite and key exchange group, or the error, and the
command exits non-zero if any target fails.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		caFile, _ := cmd.Flags().GetString("ca-file")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		roots, err := tlsProbeRoots(caFile)
		if err != nil {
			return err
		}
		targets := args
		if len(targets) == 0 {
			if targets, err = readProbeTargets(cmd.InOrStdin()); err != nil {
				return err
			}
		}
		if len(targets) == 0 {
			return errors.New("no targets: pass host:port arguments or one per line on stdin")
		}
		parent := cmd.Context()
		if parent == nil {
			parent = context.Background()
		}
		failed := 0
		for _, t := range targets {
			ctx, cancel := context.WithTimeout(parent, timeout)
			state, err := probeTLS(ctx, t, roots)
			cancel()
			if err != nil {
				failed++
				fmt.Fprintf(cmd.OutOrStdout(), "%s FAIL %v\n", probeLabel(t), err)
				continue
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s OK %s %s %s\n", probeLabel(t), tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite), state.CurveID)
		}
		if failed > 0 {
			cmd.SilenceUsage = true
			return fmt.Errorf("%d of %d handshakes failed", failed, len(targets))
		}
		return nil
	},
}

func init() {
	tlsProbeCmd.Flags().String("ca-file", "", "PEM file of extra root certificates to trust, added to the system roots")
	tlsProbeCmd.Flags().Duration("timeout", 10*time.Second, "time allowed for each target")
	rootCmd.AddCommand(tlsProbeCmd)
}

// tlsProbeRoots is the system pool the broker dials upstreams with, plus an optional extra bundle.
func tlsProbeRoots(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile == "" {
		return pool, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no certificates", caFile)
	}
	return pool, nil
}

// probeLabel is how a target is printed: scheme and host:port only, never userinfo, path or query.
func probeLabel(target string) string {
	scheme, addr := "", target
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return "invalid-target"
		}
		scheme, addr = u.Scheme+"://", u.Host
	}
	if _, _, err := net.SplitHostPort(addr); err != nil || strings.ContainsAny(addr, "@/?#") {
		return "invalid-target"
	}
	return scheme + addr
}

func readProbeTargets(r io.Reader) ([]string, error) {
	var targets []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	return targets, sc.Err()
}

// probeTLS dials one target, runs any plaintext preamble its scheme needs and completes the TLS handshake.
func probeTLS(ctx context.Context, target string, roots *x509.CertPool) (tls.ConnectionState, error) {
	scheme, addr := "tls", target
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil || u.Host == "" {
			return tls.ConnectionState{}, errors.New("invalid target URL")
		}
		scheme, addr = u.Scheme, u.Host
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || strings.ContainsAny(addr, "@/?#") {
		return tls.ConnectionState{}, errors.New("target needs host:port")
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	switch scheme {
	case "tls":
	case "postgres", "postgresql":
		err = postgresSSLRequest(conn)
	case "smtp":
		err = smtpStartTLS(conn)
	default:
		err = fmt.Errorf("unsupported scheme %q", scheme)
	}
	if err != nil {
		return tls.ConnectionState{}, err
	}
	tc := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	return tc.ConnectionState(), nil
}

func postgresSSLRequest(conn net.Conn) error {
	if _, err := conn.Write([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}); err != nil {
		return err
	}
	var resp [1]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("reading SSLRequest response: %w", err)
	}
	if resp[0] != 'S' {
		return errors.New("the database did not accept TLS")
	}
	return nil
}

func smtpStartTLS(conn net.Conn) error {
	br := bufio.NewReader(conn)
	if err := smtpExpect(br, "220"); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, "EHLO tls-probe\r\n"); err != nil {
		return err
	}
	if err := smtpExpect(br, "250"); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	return smtpExpect(br, "220")
}

// smtpExpect reads a possibly multi-line reply and checks its code.
func smtpExpect(br *bufio.Reader, code string) error {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading SMTP reply: %w", err)
		}
		if len(line) < 4 || line[:3] != code {
			return fmt.Errorf("unexpected SMTP reply %q", strings.TrimSpace(line))
		}
		if line[3] != '-' {
			return nil
		}
	}
}
