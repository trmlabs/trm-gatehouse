package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"
)

const pgRole = "staging.local.example.orders-readonly"
const imageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func setupDatabase(a authority, call func(string, string, any) obj, catalog obj) {
	a.leaf("/state/database", "database.example")
	a.leaf("/state/relay", "relay.example")
	a.leaf("/state/operator", "identity.example")
	admin := random()
	save("/state/database/password", []byte(admin))
	save("/state/database/ready", []byte("ready"))
	must(waitFile("/state/database/initialized"))
	call("POST", "sys/mounts/database", obj{"type": "database"})
	call("POST", "database/config/orders", obj{"plugin_name": "postgresql-database-plugin", "allowed_roles": []string{pgRole}, "connection_url": "postgresql://{{username}}:{{password}}@database.example:5432/orders?sslmode=verify-full&sslrootcert=/public/root.crt", "username": "playground_admin", "password": admin})
	call("POST", "database/roles/"+pgRole, obj{"db_name": "orders", "creation_statements": []string{`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE orders_reader;`}, "revocation_statements": []string{`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}'; DROP ROLE IF EXISTS "{{name}}";`}, "default_ttl": "5m", "max_ttl": "30m"})
	catalog["pools"] = append(catalog["pools"].([]any), obj{"name": "orders-workers", "namespace": "playground", "serviceAccount": "relay"})
	catalog["harnesses"] = append(catalog["harnesses"].([]any), obj{"name": "orders-relay", "trustDomain": obj{"issuer": "https://identity.example:8443", "keys": "in-cluster", "audience": "playground"}, "identity": obj{"kind": "pod-token", "ownerKind": "Job", "namespaces": []string{"playground"}, "imageDigests": []string{imageDigest}}, "path": obj{"kind": "sidecar"}, "authorization": obj{"mode": "pool", "poolName": "orders-workers"}, "client": obj{"proxyEnv": "HTTPS_PROXY", "caFileEnv": "SSL_CERT_FILE"}})
	catalog["entries"] = append(catalog["entries"].([]any), obj{"name": "orders", "kind": "postgres", "host": "database.example", "pools": []string{"orders-workers"}, "postgres": obj{"database": "orders", "mount": "database", "role": pgRole}})
	reviewer := random()
	save("/state/broker/reviewer", []byte(reviewer))
	save("/state/relay/reviewer", []byte(reviewer))
	saveJSON("/state/broker/identity.json", obj{"apiServer": "https://identity.example:8443", "caFile": "/public/root.crt", "reviewerTokenFile": "/state/reviewer", "issuer": "https://identity.example:8443", "audience": "playground", "bindings": []any{obj{"namespace": "playground", "serviceAccount": "relay", "serviceAccountUID": "relay-account", "ownerUIDs": []string{"playground-controller"}, "containerName": "relay", "maxPodSeconds": 86400, "pool": "orders-workers", "imageDigests": []string{imageDigest}}}})
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(e)
	jwks := obj{"keys": []any{obj{"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "playground", "x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), "y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}}}
	mint := func() {
		now := time.Now()
		claims := obj{"iss": "https://identity.example:8443", "sub": "system:serviceaccount:playground:relay", "aud": []string{"playground"}, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "kubernetes.io": obj{"namespace": "playground", "serviceaccount": obj{"name": "relay", "uid": "relay-account"}, "pod": obj{"name": "relay", "uid": "playground-relay"}}}
		b, _ := json.Marshal(claims)
		head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"playground"}`))
		signed := head + "." + base64.RawURLEncoding.EncodeToString(b)
		h := sha256.Sum256([]byte(signed))
		r, s, e := ecdsa.Sign(rand.Reader, key, h[:])
		must(e)
		sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		save("/state/relay/proof", []byte(signed+"."+base64.RawURLEncoding.EncodeToString(sig)))
	}
	mint()
	go func() {
		for {
			time.Sleep(20 * time.Minute)
			mint()
		}
	}()
	started := time.Now().UTC().Format(time.RFC3339)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+reviewer {
			http.Error(w, "Denied", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/openid/v1/jwks":
			_ = json.NewEncoder(w).Encode(jwks)
		case "/api/v1/namespaces/playground/pods/relay":
			_ = json.NewEncoder(w).Encode(obj{"metadata": obj{"name": "relay", "namespace": "playground", "uid": "playground-relay", "ownerReferences": []any{obj{"kind": "Job", "uid": "playground-controller", "controller": true, "blockOwnerDeletion": true}}}, "spec": obj{"serviceAccountName": "relay"}, "status": obj{"phase": "Running", "podIP": resolve("relay-broker"), "startTime": started, "containerStatuses": []any{obj{"name": "relay", "imageID": imageDigest, "restartCount": 0, "state": obj{"running": obj{"startedAt": started}}}}}})
		case "/api/v1/namespaces/playground/pods/sandbox":
			b, e := os.ReadFile("/state/relay/pair.json")
			if e != nil {
				http.Error(w, "Not ready", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write(b)
		default:
			http.NotFound(w, r)
		}
	})
	go func() {
		s := &http.Server{Addr: ":8443", Handler: h, ReadHeaderTimeout: 5 * time.Second}
		must(s.ListenAndServeTLS("/state/operator/tls.crt", "/state/operator/tls.key"))
	}()
}
func database() error {
	if e := waitFile("/state/ready"); e != nil {
		return e
	}
	init := exec.Command("initdb", "-D", "/root/pg", "-U", "playground_admin", "--auth-local=trust", "--auth-host=scram-sha-256", "--pwfile=/state/password")
	init.Stdout = io.Discard
	init.Stderr = os.Stderr
	if e := init.Run(); e != nil {
		return e
	}
	save("/root/pg/pg_hba.conf", []byte("local all all trust\nhostssl all all all scram-sha-256\n"))
	cmd := exec.Command("pg_ctl", "-D", "/root/pg", "-l", "/root/pg.log", "-o", "-h 0.0.0.0 -k /root -c ssl=on -c ssl_cert_file=/state/tls.crt -c ssl_key_file=/state/tls.key", "-w", "start")
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	if e := cmd.Run(); e != nil {
		return e
	}
	sql := func(db, q string) {
		cmd := exec.Command("psql", "-X", "-h", "/root", "-U", "playground_admin", "-d", db, "-v", "ON_ERROR_STOP=1", "-c", q)
		cmd.Stdout = io.Discard
		cmd.Stderr = os.Stderr
		must(cmd.Run())
	}
	sql("postgres", "CREATE DATABASE orders")
	sql("orders", "CREATE TABLE refunds(order_id integer, refunds integer, cause text); INSERT INTO refunds VALUES (1,2,'duplicate scheduler'),(2,2,'duplicate scheduler'); REVOKE CREATE ON SCHEMA public FROM PUBLIC; CREATE ROLE orders_reader NOLOGIN; GRANT CONNECT ON DATABASE orders TO orders_reader; GRANT USAGE ON SCHEMA public TO orders_reader; GRANT SELECT ON refunds TO orders_reader;")
	save("/state/initialized", []byte("ready"))
	for {
		time.Sleep(time.Hour)
	}
}
func startDatabaseRelay() error {
	ip := resolve("sandbox")
	started := time.Now().UTC().Format(time.RFC3339)
	saveJSON("/state/pair.json", obj{"metadata": obj{"namespace": "playground", "name": "sandbox", "uid": "playground-sandbox"}, "status": obj{"phase": "Running", "podIP": ip, "containerStatuses": []any{obj{"name": "shell", "restartCount": 0, "state": obj{"running": obj{"startedAt": started}}}}}})
	saveJSON("/state/pg-relay.json", obj{"taskID": "playground", "deadline": time.Now().Add(23 * time.Hour).UTC().Format(time.RFC3339), "sandbox": obj{"namespace": "playground", "name": "sandbox", "uid": "playground-sandbox", "podIP": ip, "containerName": "shell"}, "kubernetes": obj{"apiURL": "https://identity.example:8443", "caFile": "/public/root.crt", "reviewerTokenFile": "/state/reviewer"}, "tlsCertFile": "/state/tls.crt", "tlsKeyFile": "/state/tls.key", "auditFile": "/state/pg-audit.jsonl", "postgres": obj{"listen": "0.0.0.0:15443", "database": "orders", "user": "workload", "placeholder": "orders-placeholder", "upstream": obj{"address": "broker.example:15443", "serverName": "broker.example", "caFile": "/public/root.crt", "proofFile": "/state/proof", "audience": "playground"}}})
	cmd := exec.Command("agent-vault", "task-relay", "--config", "/state/pg-relay.json")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if e := cmd.Start(); e != nil {
		return e
	}
	go func() {
		if e := cmd.Wait(); e != nil {
			fmt.Fprintln(os.Stderr, "Database relay stopped")
		}
	}()
	return nil
}
func databaseTunnel() {
	l, e := net.Listen("tcp", "127.0.0.1:15432")
	must(e)
	cfg := tlsConfig("/public/root.crt")
	cfg.ServerName = "relay.example"
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		go func() {
			b, e := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", "relay:15443", cfg)
			if e != nil {
				_ = c.Close()
				return
			}
			pipe(c, b)
		}()
	}
}
