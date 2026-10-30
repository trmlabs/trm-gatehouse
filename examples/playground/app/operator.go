package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newAuthority() authority {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(e)
	template := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Playground transport CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(e)
	cert, e := x509.ParseCertificate(der)
	must(e)
	return authority{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}
func serial() *big.Int {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	must(e)
	return n
}
func (a authority) leaf(dir, name string) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(e)
	t := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, t, a.cert, &key.PublicKey, a.key)
	must(e)
	pk, e := x509.MarshalECPrivateKey(key)
	must(e)
	save(dir+"/tls.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	save(dir+"/tls.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pk}))
}
func vaultCall(c *http.Client, token, method, path string, data any) (obj, error) {
	var body io.Reader
	if data != nil {
		b, e := json.Marshal(data)
		if e != nil {
			return nil, e
		}
		body = strings.NewReader(string(b))
	}
	r, e := http.NewRequest(method, "https://vault.example:8443/v1/"+path, body)
	if e != nil {
		return nil, e
	}
	r.Header.Set("X-Vault-Token", token)
	r.Header.Set("Content-Type", "application/json")
	resp, e := c.Do(r)
	if e != nil {
		return nil, e
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vault operation %s failed (%d)", path, resp.StatusCode)
	}
	var result obj
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}
func operator() error {
	a := newAuthority()
	save("/public/root.crt", a.pem)
	for _, name := range []string{"vault", "broker", "payments", "logs", "attacker"} {
		a.leaf("/state/"+name, name+".example")
	}
	root := random()
	save("/state/vault/root", []byte(root))
	save("/state/vault/ready", []byte("ready"))
	c := client("/public/root.crt")
	for i := 0; i < 600; i++ {
		_, e := vaultCall(c, root, "GET", "sys/health", nil)
		if e == nil {
			break
		}
		if i == 599 {
			return e
		}
		time.Sleep(200 * time.Millisecond)
	}
	call := func(method, path string, data any) obj {
		v, e := vaultCall(c, root, method, path, data)
		must(e)
		return v
	}
	call("POST", "sys/mounts/gatehouse", obj{"type": "kv", "options": obj{"version": "2"}})
	call("POST", "sys/mounts/transit", obj{"type": "transit"})
	call("POST", "transit/keys/playground-signing", obj{"type": "ed25519"})
	keyBytes := make([]byte, 32)
	_, e := rand.Read(keyBytes)
	must(e)
	call("POST", "gatehouse/data/playground-audit", obj{"data": obj{"key": base64.StdEncoding.EncodeToString(keyBytes)}})
	payments, logs, decoy := random(), random(), random()
	put := func(name, key string) { call("POST", "gatehouse/data/vendors/"+name, obj{"data": obj{"key": key}}) }
	put("payments", payments)
	put("logs", logs)
	save("/state/payments/key", []byte(payments))
	save("/state/logs/key", []byte(logs))
	save("/public/decoy", []byte(decoy))
	call("POST", "gatehouse/data/decoys/pools/playground", obj{"data": obj{"backup": decoy}})
	call("POST", "gatehouse/data/decoys/head", obj{"data": obj{"names": []string{"playground"}}})
	secret := make([]byte, 32)
	_, e = rand.Read(secret)
	must(e)
	token := "playground-run." + base64.RawURLEncoding.EncodeToString(secret)
	save("/state/relay/token", []byte(token))
	targets := []targetHash{{Name: "Payments key", SHA256: hash(payments), Length: len(payments)}, {Name: "Logs token", SHA256: hash(logs), Length: len(logs)}, {Name: "Relay login", SHA256: hash(token), Length: len(token)}}
	saveJSON("/public/targets.json", targets)
	entry := func(name, host, placeholder string, paths, methods []string) obj {
		return obj{"name": name, "host": host, "port": 443, "pathPrefixes": paths, "methods": methods, "header": "Authorization", "scheme": "Bearer", "placeholder": placeholder, "key": obj{"mount": "gatehouse", "path": "vendors/" + name, "field": "key"}, "pools": []string{"playground"}}
	}
	catalog := obj{"harnesses": []any{obj{"name": "playground-token", "identity": obj{"kind": "static-token"}, "path": obj{"kind": "direct"}, "authorization": obj{"mode": "automation", "poolName": "playground"}, "client": obj{"proxyEnv": "HTTPS_PROXY", "caFileEnv": "SSL_CERT_FILE"}}}, "pools": []any{obj{"name": "playground", "namespace": "playground", "serviceAccount": "agent", "identity": "cursor-automation"}}, "entries": []any{entry("payments", "payments.example", "__vault_PAYMENTS_KEY__", []string{"/refunds", "/echo", "/redirect", "/notes", "/scheduler/disable-duplicate", "/scheduler/test-run"}, []string{"GET", "POST"}), entry("logs", "logs.example", "__vault_LOGS_TOKEN__", []string{"/mcp"}, []string{"POST"})}, "automations": []any{obj{"id": "playground-run", "name": "refund-investigator", "owner": "example-team", "entries": []string{"payments", "logs"}, "tokenSHA256": []string{hash(token)}, "expires": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)}}}
	setupDatabase(a, call, catalog)
	saveJSON("/state/broker/catalog.json", catalog)
	policy := `path "gatehouse/data/vendors/payments" { capabilities = ["read"] }
path "gatehouse/data/vendors/logs" { capabilities = ["read"] }
path "gatehouse/data/playground-audit" { capabilities = ["read"] }
path "gatehouse/data/decoys/*" { capabilities = ["read"] }
path "transit/sign/playground-signing" { capabilities = ["update"] }
path "database/creds/staging.local.example.orders-readonly" { capabilities = ["read"] }
path "sys/leases/renew" { capabilities = ["update"] }
path "sys/leases/revoke/database/creds/staging.local.example.orders-readonly/*" { capabilities = ["update"] }
path "sys/leases/lookup" { capabilities = ["update"] }
path "auth/token/create" { capabilities = ["update"] }`
	call("PUT", "sys/policies/acl/playground-broker", obj{"policy": policy})
	childPolicy := "agent-vault-db-" + hash("database/creds/"+pgRole)
	call("PUT", "sys/policies/acl/"+childPolicy, obj{"policy": `path "database/creds/` + pgRole + `" { capabilities = ["read"] }
path "auth/token/revoke-self" { capabilities = ["update"] }`})
	tok := call("POST", "auth/token/create", obj{"policies": []string{"playground-broker", childPolicy}, "ttl": "24h", "renewable": true})["auth"].(map[string]any)["client_token"].(string)
	saveJSON("/state/broker/env.json", map[string]string{"AGENT_VAULT_MASTER_PASSWORD": random(), "AGENT_VAULT_DB_BROKER": "true", "AGENT_VAULT_DB_PROXY_PROTOCOL": "true", "AGENT_VAULT_CATALOG_ENVIRONMENT": "staging", "VAULT_ADDR": "https://vault.example:8443", "VAULT_TOKEN": tok, "VAULT_CACERT": "/public/root.crt", "SSL_CERT_FILE": "/public/root.crt", "AGENT_VAULT_CREDENTIAL_PROXY": "true", "AGENT_VAULT_TELEMETRY": "false", "AGENT_VAULT_ALLOW_PRIVATE_RANGES": "true", "AGENT_VAULT_HTTP_CATALOG_FILE": "/state/catalog.json", "AGENT_VAULT_WORKLOAD_IDENTITY_FILE": "/state/identity.json", "AGENT_VAULT_MITM_PROXY_PROTOCOL": "true", "AGENT_VAULT_STATIC_TOKEN_PORT": "14326", "AGENT_VAULT_AUDIT_CHAIN": "1", "AGENT_VAULT_AUDIT_HMAC_PATH": "playground-audit", "AGENT_VAULT_AUDIT_TRANSIT_KEY": "playground-signing", "AGENT_VAULT_REPLICA": "playground", "AGENT_VAULT_DECOY_VAULT_PREFIX": "gatehouse/decoys"})
	for _, name := range []string{"payments", "logs", "attacker", "broker", "relay"} {
		save("/state/"+name+"/ready", []byte("ready"))
	}
	save("/state/baseline/key", []byte(random()))
	save("/state/baseline/ready", []byte("ready"))
	saveJSON("/status/operator.json", obj{"rotation": 0, "status": "Ready"})
	rotation := 0
	saveJSON("/public/run.json", demoRun{ID: random(), Started: time.Now().UTC()})
	for {
		if _, e := os.Stat("/control/reset"); e == nil {
			_ = os.Remove("/control/reset")
			_ = os.Remove("/control/run")
			_ = os.Remove("/control/rotate")
			saveJSON("/public/run.json", demoRun{ID: random(), Started: time.Now().UTC()})
		}
		if _, e := os.Stat("/control/rotate"); e == nil {
			_ = os.Remove("/control/rotate")
			payments = random()
			put("payments", payments)
			save("/state/payments/key", []byte(payments))
			targets = append(targets, targetHash{Name: "Payments key", SHA256: hash(payments), Length: len(payments)})
			saveJSON("/public/targets.json", targets)
			rotation++
			saveJSON("/status/operator.json", obj{"rotation": rotation, "vaultWrite": obj{"method": "POST", "path": "/v1/gatehouse/data/vendors/payments", "run": currentRun().ID, "completedAt": time.Now().UTC().Format(time.RFC3339Nano)}, "status": "Key rotated. An old cached key may receive 401; retry to use the new key."})
		}
		time.Sleep(200 * time.Millisecond)
	}
}
