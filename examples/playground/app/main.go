package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type obj = map[string]any

func main() {
	log.SetFlags(0)
	if filepath.Base(os.Args[0]) == "request" {
		request(os.Args[1:])
		return
	}
	if len(os.Args) < 2 {
		log.Fatal("choose operator, broker, vault, relay, payments, logs, attacker, baseline, sandbox or web")
	}
	var err error
	switch os.Args[1] {
	case "probe":
		if len(os.Args) != 3 {
			log.Fatal("probe requires address")
		}
		conn, e := net.DialTimeout("tcp", os.Args[2], time.Second)
		if e == nil {
			_ = conn.Close()
			err = errors.New("unexpected direct connection")
		}
	case "database":
		err = database()
	case "operator":
		err = operator()
	case "broker":
		err = broker()
	case "vault":
		err = vault()
	case "relay":
		err = relay()
	case "payments", "logs", "attacker":
		err = site(os.Args[1])
	case "baseline":
		err = baseline()
	case "sandbox":
		err = sandbox()
	case "web":
		err = web()
	default:
		err = errors.New("unknown role")
	}
	if err != nil {
		log.Fatal(err)
	}
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(p string) string { b, e := os.ReadFile(p); must(e); return strings.TrimSpace(string(b)) }
func save(p string, b []byte) {
	must(os.MkdirAll(filepath.Dir(p), 0700))
	must(os.WriteFile(p+".next", b, 0600))
	must(os.Rename(p+".next", p))
}
func saveJSON(p string, v any) { b, e := json.Marshal(v); must(e); save(p, b) }
func random() string {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	must(e)
	return "demo_" + hex.EncodeToString(b)
}
func hash(v string) string { b := sha256.Sum256([]byte(v)); return hex.EncodeToString(b[:]) }
func waitFile(p string) error {
	for i := 0; i < 600; i++ {
		if _, e := os.Stat(p); e == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", p)
}
func tlsConfig(ca string) *tls.Config {
	pool := x509.NewCertPool()
	b, e := os.ReadFile(ca)
	must(e)
	if !pool.AppendCertsFromPEM(b) {
		panic("invalid public CA")
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}
func client(ca string) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig(ca)}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func serve(address string, h http.Handler) error {
	s := &http.Server{Addr: address, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	return s.ListenAndServe()
}
func serveTLS(address string, h http.Handler) error {
	s := &http.Server{Addr: address, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	return s.ListenAndServeTLS("/state/tls.crt", "/state/tls.key")
}
func peer(r *http.Request) string { h, _, _ := net.SplitHostPort(r.RemoteAddr); return h }
func resolve(name string) string {
	for i := 0; i < 100; i++ {
		ips, e := net.LookupIP(name)
		if e == nil {
			for _, ip := range ips {
				if ip.To4() != nil {
					return ip.String()
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	panic("cannot resolve " + name)
}
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}

func front(address, upstream string, proxyHeader bool) error {
	cert, e := tls.LoadX509KeyPair("/state/tls.crt", "/state/tls.key")
	if e != nil {
		return e
	}
	l, e := tls.Listen("tcp", address, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if e != nil {
		return e
	}
	for {
		c, e := l.Accept()
		if e != nil {
			return e
		}
		go func() {
			_ = c.SetDeadline(time.Now().Add(30 * time.Minute))
			b, e := net.DialTimeout("tcp", upstream, 5*time.Second)
			if e != nil {
				_ = c.Close()
				return
			}
			if proxyHeader {
				h, p, _ := net.SplitHostPort(c.RemoteAddr().String())
				local, port, _ := net.SplitHostPort(b.LocalAddr().String())
				_, e = fmt.Fprintf(b, "PROXY TCP4 %s %s %s %s\r\n", h, local, p, port)
				if e != nil {
					_ = c.Close()
					_ = b.Close()
					return
				}
			}
			pipe(c, b)
		}()
	}
}
func vault() error {
	if e := waitFile("/state/ready"); e != nil {
		return e
	}
	cmd := exec.Command("vault", "server", "-dev", "-dev-no-store-token", "-dev-root-token-id="+read("/state/root"), "-dev-listen-address=127.0.0.1:8200")
	cmd.Env = append(os.Environ(), "SKIP_SETCAP=true")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e := cmd.Start(); e != nil {
		return e
	}
	go func() {
		if e := cmd.Wait(); e != nil {
			log.Fatal("Vault stopped")
		}
	}()
	return front(":8443", "127.0.0.1:8200", false)
}
func broker() error {
	if e := waitFile("/state/ready"); e != nil {
		return e
	}
	var settings map[string]string
	must(json.Unmarshal([]byte(read("/state/env.json")), &settings))
	cmd := exec.Command("agent-vault", "server", "--host", "127.0.0.1", "--port", "14321", "--mitm-port", "14322", "--postgres-port", "14323")
	settings["AGENT_VAULT_EGRESS_RANGES"] = resolve("payments.example") + "/32," + resolve("logs.example") + "/32," + resolve("attacker.example") + "/32," + resolve("database.example") + "/32"
	cmd.Env = os.Environ()
	for k, v := range settings {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		return e
	}
	cmd.Stderr = os.Stderr
	if e = cmd.Start(); e != nil {
		return e
	}
	go func() {
		f, e := os.OpenFile("/audit/audit.jsonl", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		must(e)
		defer func() { _ = f.Close() }()
		s := bufio.NewScanner(out)
		s.Buffer(make([]byte, 4096), 1<<20)
		for s.Scan() {
			var row obj
			if json.Unmarshal(s.Bytes(), &row) == nil && row["type"] == "gatehouse.audit.v1" {
				if stat, err := f.Stat(); err != nil || stat.Size() > 16<<20 {
					_ = cmd.Process.Kill()
					log.Fatal("Audit feed full or unavailable; restart the lab")
				}
				if _, err := f.Write(append(append([]byte{}, s.Bytes()...), '\n')); err != nil {
					_ = cmd.Process.Kill()
					log.Fatal("Audit feed unavailable")
				}
			} else {
				fmt.Fprintln(os.Stdout, s.Text())
			}
		}
	}()
	go func() {
		if e := cmd.Wait(); e != nil {
			log.Fatal("Gatehouse stopped")
		}
	}()
	for i := 0; i < 600; i++ {
		c := &http.Client{Timeout: time.Second}
		r, e := c.Get("http://127.0.0.1:14321/v1/mitm/ca.pem")
		if e == nil {
			b, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			if r.StatusCode == 200 {
				save("/public/interception.crt", b)
				break
			}
		}
		if i == 599 {
			return errors.New("gatehouse startup timed out")
		}
		time.Sleep(200 * time.Millisecond)
	}
	go func() { must(front(":15443", "127.0.0.1:14323", true)) }()
	return front(":8443", "127.0.0.1:14326", true)
}
func relay() error {
	if e := waitFile("/state/ready"); e != nil {
		return e
	}
	if e := startDatabaseRelay(); e != nil {
		return e
	}
	allowed := resolve("sandbox")
	token := read("/state/token")
	cfg := tlsConfig("/public/root.crt")
	cfg.ServerName = "broker.example"
	return serve(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if peer(r) != allowed || r.Method != "CONNECT" || r.Header.Get("Proxy-Authorization") != "" {
			http.Error(w, "Relay refused", http.StatusForbidden)
			return
		}
		host, port, e := net.SplitHostPort(r.Host)
		if e != nil || port != "443" || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
			http.Error(w, "Use a DNS name on port 443", http.StatusForbidden)
			return
		}
		b, e := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", "broker.example:8443", cfg)
		if e != nil {
			http.Error(w, "Gatehouse unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = b.SetDeadline(time.Now().Add(30 * time.Minute))
		_, e = fmt.Fprintf(b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", r.Host, r.Host, base64.StdEncoding.EncodeToString([]byte(token+":")))
		if e != nil {
			_ = b.Close()
			http.Error(w, "Gatehouse unavailable", http.StatusServiceUnavailable)
			return
		}
		br := bufio.NewReader(b)
		response, e := http.ReadResponse(br, r)
		if e != nil {
			_ = b.Close()
			http.Error(w, "Gatehouse unavailable", http.StatusServiceUnavailable)
			return
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != 200 {
			_ = b.Close()
			http.Error(w, "Gatehouse refused this tunnel", response.StatusCode)
			return
		}
		c, buf, e := w.(http.Hijacker).Hijack()
		if e != nil {
			_ = b.Close()
			return
		}
		_, _ = buf.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		_ = buf.Flush()
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(c, br); done <- struct{}{} }()
		go func() { _, _ = io.Copy(b, buf); done <- struct{}{} }()
		<-done
		_ = c.Close()
		_ = b.Close()
		<-done
	}))
}
func request(args []string) {
	method := "GET"
	body := ""
	headers := http.Header{}
	target := ""
	follow := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-X":
			i++
			if i < len(args) {
				method = args[i]
			}
		case "-H":
			i++
			if i < len(args) {
				k, v, ok := strings.Cut(args[i], ":")
				if ok {
					headers.Add(k, strings.TrimSpace(v))
				}
			}
		case "-d", "--data":
			i++
			if i < len(args) {
				body = args[i]
				if method == "GET" {
					method = "POST"
				}
			}
		case "-L":
			follow = true
		case "-i", "-s":
		default:
			target = args[i]
		}
	}
	if target == "" || target == "--help" {
		fmt.Println("request [-X METHOD] [-H 'Name: value'] [-d body] [-L] https://payments.example/refunds")
		return
	}
	cfg := tlsConfig("/public/interception.crt")
	proxyURL, _ := url.Parse("http://relay:8080")
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: cfg}, Timeout: 15 * time.Second}
	if !follow {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r, e := http.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	if e != nil {
		fmt.Println("Invalid request")
		return
	}
	r.Header = headers
	resp, e := c.Do(r)
	if e != nil {
		fmt.Println("Request refused or connection failed:", e)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	fmt.Println(resp.Status)
	if v := resp.Header.Get("X-Gatehouse-Refusal"); v != "" {
		fmt.Println("X-Gatehouse-Refusal:", v)
	}
	_, _ = io.Copy(os.Stdout, io.LimitReader(resp.Body, 256<<10))
	fmt.Println()
}
